package awsx

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// interfaceRetry is the time between reads of an instance that is not running
// yet, and between tries to delete an interface that is still attached.
var interfaceRetry = 5 * time.Second

// AttachNewInterface makes a network interface with the tags in the subnet and
// with the security groups of the instance, attaches it to the instance at
// device index 1, and sets it to go with the instance at termination. It waits
// until wait ends for the instance to run. It deletes the interface when a step
// after the create fails. It returns the interface ID.
func (c *Client) AttachNewInterface(ctx context.Context, instanceID string, tags map[string]string, wait time.Duration) (string, error) {
	inst, err := c.runningInstance(ctx, instanceID, wait)
	if err != nil {
		return "", err
	}
	groups := make([]string, 0, len(inst.SecurityGroups))
	for _, g := range inst.SecurityGroups {
		groups = append(groups, aws.ToString(g.GroupId))
	}
	out, err := c.ec2.CreateNetworkInterface(ctx, &ec2.CreateNetworkInterfaceInput{
		SubnetId:          inst.SubnetId,
		Groups:            groups,
		Description:       aws.String("perf bench interface of " + instanceID),
		TagSpecifications: []types.TagSpecification{{ResourceType: types.ResourceTypeNetworkInterface, Tags: ec2Tags(tags)}},
	})
	if err != nil {
		return "", fmt.Errorf("create a network interface for %s: %w", instanceID, err)
	}
	id := aws.ToString(out.NetworkInterface.NetworkInterfaceId)
	if err := c.attach(ctx, instanceID, id); err != nil {
		// A failed attach leaves the interface available, so the delete works at once.
		ctx := context.WithoutCancel(ctx)
		if _, derr := c.ec2.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: aws.String(id)}); derr != nil {
			err = errors.Join(err, fmt.Errorf("delete network interface %s: %w", id, derr))
		}
		return "", err
	}
	return id, nil
}

// attach attaches the interface at device index 1 and sets it to go with the instance.
func (c *Client) attach(ctx context.Context, instanceID, id string) error {
	att, err := c.ec2.AttachNetworkInterface(ctx, &ec2.AttachNetworkInterfaceInput{
		InstanceId:         aws.String(instanceID),
		NetworkInterfaceId: aws.String(id),
		DeviceIndex:        aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("attach network interface %s to %s: %w", id, instanceID, err)
	}
	_, err = c.ec2.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(id),
		Attachment: &types.NetworkInterfaceAttachmentChanges{
			AttachmentId:        att.AttachmentId,
			DeleteOnTermination: aws.Bool(true),
		},
	})
	if err == nil {
		return nil
	}
	err = fmt.Errorf("set network interface %s to go with %s: %w", id, instanceID, err)
	// The delete after a failure needs an available interface.
	if _, derr := c.ec2.DetachNetworkInterface(context.WithoutCancel(ctx), &ec2.DetachNetworkInterfaceInput{
		AttachmentId: att.AttachmentId, Force: aws.Bool(true),
	}); derr != nil {
		return errors.Join(err, fmt.Errorf("detach network interface %s: %w", id, derr))
	}
	return errors.Join(err, c.waitAvailable(context.WithoutCancel(ctx), id, time.Minute))
}

// runningInstance reads the instance until it runs or wait ends.
func (c *Client) runningInstance(ctx context.Context, id string, wait time.Duration) (types.Instance, error) {
	deadline := time.Now().Add(wait)
	for {
		out, err := c.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
		if err != nil && apiCode(err) != "InvalidInstanceID.NotFound" {
			return types.Instance{}, fmt.Errorf("describe instance %s: %w", id, err)
		}
		state := "not-found"
		if err == nil {
			for _, r := range out.Reservations {
				for _, i := range r.Instances {
					if i.State == nil {
						continue
					}
					if state = string(i.State.Name); i.State.Name == types.InstanceStateNameRunning {
						return i, nil
					}
				}
			}
		}
		if state != "pending" && state != "not-found" {
			return types.Instance{}, fmt.Errorf("instance %s is %s, not running", id, state)
		}
		if time.Now().After(deadline) {
			return types.Instance{}, fmt.Errorf("instance %s is %s after %s", id, state, wait)
		}
		select {
		case <-ctx.Done():
			return types.Instance{}, ctx.Err()
		case <-time.After(interfaceRetry):
		}
	}
}

// waitAvailable waits until the interface is available or gone, or wait ends.
func (c *Client) waitAvailable(ctx context.Context, id string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		out, err := c.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{id}})
		if apiCode(err) == "InvalidNetworkInterfaceID.NotFound" {
			return nil
		}
		if err != nil {
			return fmt.Errorf("describe network interface %s: %w", id, err)
		}
		if len(out.NetworkInterfaces) == 0 || out.NetworkInterfaces[0].Status == types.NetworkInterfaceStatusAvailable {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("network interface %s is %s after %s", id, out.NetworkInterfaces[0].Status, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interfaceRetry):
		}
	}
}

// taggedInterfaces returns the network interfaces with the tag KEY=VALUE.
func (c *Client) taggedInterfaces(ctx context.Context, tag string) ([]types.NetworkInterface, error) {
	k, v, ok := strings.Cut(tag, "=")
	if !ok || k == "" {
		return nil, fmt.Errorf("bad tag %q: want KEY=VALUE", tag)
	}
	in := &ec2.DescribeNetworkInterfacesInput{Filters: []types.Filter{{Name: aws.String("tag:" + k), Values: []string{v}}}}
	var found []types.NetworkInterface
	pages := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2, in)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe network interfaces: %w", err)
		}
		found = append(found, page.NetworkInterfaces...)
	}
	return found, nil
}

// NetworkInterfaces returns the network interfaces with the tag KEY=VALUE, each
// as its ID and its status.
func (c *Client) NetworkInterfaces(ctx context.Context, tag string) ([]string, error) {
	enis, err := c.taggedInterfaces(ctx, tag)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(enis))
	for _, e := range enis {
		out = append(out, aws.ToString(e.NetworkInterfaceId)+" "+string(e.Status))
	}
	slices.Sort(out)
	return out, nil
}

// DeleteNetworkInterfaces deletes the network interfaces with the tag KEY=VALUE
// and returns their IDs. While an interface is attached, for example to an
// instance that terminates, it tries again until wait ends. An interface that
// EC2 deletes with its instance is not an error.
func (c *Client) DeleteNetworkInterfaces(ctx context.Context, tag string, wait time.Duration) ([]string, error) {
	enis, err := c.taggedInterfaces(ctx, tag)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	var deleted []string
	var errs []error
	for _, e := range enis {
		id := aws.ToString(e.NetworkInterfaceId)
		gone, err := c.deleteInterface(ctx, id, deadline)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !gone {
			deleted = append(deleted, id)
		}
	}
	return deleted, errors.Join(errs...)
}

// deleteInterface deletes the interface. gone tells that EC2 did not know it.
func (c *Client) deleteInterface(ctx context.Context, id string, deadline time.Time) (gone bool, err error) {
	for {
		_, err := c.ec2.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: aws.String(id)})
		if apiCode(err) == "InvalidNetworkInterfaceID.NotFound" {
			return true, nil
		}
		if interfaceInUse(err) {
			if time.Now().After(deadline) {
				return false, fmt.Errorf("delete network interface %s: %w", id, err)
			}
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(interfaceRetry):
			}
			continue
		}
		if err != nil {
			return false, fmt.Errorf("delete network interface %s: %w", id, err)
		}
		return false, nil
	}
}

// interfaceInUse reports whether a delete failed because the interface is attached. EC2 answers
// InvalidParameterValue "... is currently in use" for an interface that is attached.
func interfaceInUse(err error) bool {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.ErrorCode() == "InvalidNetworkInterface.InUse" ||
		ae.ErrorCode() == "InvalidParameterValue" && strings.Contains(ae.ErrorMessage(), "in use")
}

// ReapNetworkInterfaces deletes the available network interfaces with the tag
// KEY=VALUE whose RFC 3339 expiry tag is before now or not valid, and returns
// their IDs.
func (c *Client) ReapNetworkInterfaces(ctx context.Context, tag, expiryKey string, now time.Time) ([]string, error) {
	enis, err := c.taggedInterfaces(ctx, tag)
	if err != nil {
		return nil, err
	}
	var deleted []string
	var errs []error
	for _, e := range enis {
		if e.Status != types.NetworkInterfaceStatusAvailable || tagTime(e.TagSet, expiryKey).After(now) {
			continue
		}
		id := aws.ToString(e.NetworkInterfaceId)
		_, err := c.ec2.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: aws.String(id)})
		if interfaceInUse(err) || apiCode(err) == "InvalidNetworkInterfaceID.NotFound" {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("delete network interface %s: %w", id, err))
			continue
		}
		deleted = append(deleted, id)
	}
	return deleted, errors.Join(errs...)
}
