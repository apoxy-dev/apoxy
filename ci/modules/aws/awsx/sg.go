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
)

// deleteSecurityGroupRetry is the time between tries to delete a security group
// that instances use.
var deleteSecurityGroupRetry = 10 * time.Second

// publicIPRetry is the time between reads of an instance that has no public IP yet.
var publicIPRetry = 3 * time.Second

// CreateSecurityGroup makes a security group with the name and the tags in the VPC
// that Launch uses with subnetTag, and returns its ID. The members of the group can
// send to each other. It returns the group with the name that the VPC has already.
func (c *Client) CreateSecurityGroup(ctx context.Context, name, subnetTag string, tags map[string]string) (string, error) {
	subnets, _, err := c.placement(ctx, subnetTag)
	if err != nil {
		return "", err
	}
	vpc := subnets[0].vpc
	out, err := c.ec2.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:         aws.String(name),
		Description:       aws.String("Hosts of one perf bench run"),
		VpcId:             aws.String(vpc),
		TagSpecifications: []types.TagSpecification{{ResourceType: types.ResourceTypeSecurityGroup, Tags: ec2Tags(tags)}},
	})
	if apiCode(err) == "InvalidGroup.Duplicate" {
		return c.securityGroup(ctx, []types.Filter{
			{Name: aws.String("group-name"), Values: []string{name}},
			{Name: aws.String("vpc-id"), Values: []string{vpc}},
		})
	}
	if err != nil {
		return "", fmt.Errorf("create security group %s: %w", name, err)
	}
	id := aws.ToString(out.GroupId)
	all := types.IpPermission{IpProtocol: aws.String("-1"), UserIdGroupPairs: []types.UserIdGroupPair{{GroupId: aws.String(id)}}}
	if err := c.authorize(ctx, id, all); err != nil {
		return "", err
	}
	return id, nil
}

// AllowFrom lets the addresses of cidrs send all traffic to the members of the group.
func (c *Client) AllowFrom(ctx context.Context, group string, cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}
	all := types.IpPermission{IpProtocol: aws.String("-1")}
	for _, cidr := range cidrs {
		all.IpRanges = append(all.IpRanges, types.IpRange{CidrIp: aws.String(cidr)})
	}
	return c.authorize(ctx, group, all)
}

func (c *Client) authorize(ctx context.Context, group string, p types.IpPermission) error {
	_, err := c.ec2.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(group), IpPermissions: []types.IpPermission{p},
	})
	if err != nil && apiCode(err) != "InvalidPermission.Duplicate" {
		return fmt.Errorf("add an ingress rule to security group %s: %w", group, err)
	}
	return nil
}

// taggedGroups returns the security groups with the tag KEY=VALUE.
func (c *Client) taggedGroups(ctx context.Context, tag string) ([]types.SecurityGroup, error) {
	k, v, ok := strings.Cut(tag, "=")
	if !ok || k == "" {
		return nil, fmt.Errorf("bad tag %q: want KEY=VALUE", tag)
	}
	out, err := c.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{{Name: aws.String("tag:" + k), Values: []string{v}}},
	})
	if err != nil {
		return nil, fmt.Errorf("describe security groups: %w", err)
	}
	return out.SecurityGroups, nil
}

// SecurityGroups returns the security groups with the tag KEY=VALUE, each as its
// ID and its name.
func (c *Client) SecurityGroups(ctx context.Context, tag string) ([]string, error) {
	groups, err := c.taggedGroups(ctx, tag)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, aws.ToString(g.GroupId)+" "+aws.ToString(g.GroupName))
	}
	slices.Sort(names)
	return names, nil
}

// DeleteSecurityGroups deletes the security groups with the tag KEY=VALUE and
// returns their IDs. While an instance uses a group, it tries again until wait ends.
func (c *Client) DeleteSecurityGroups(ctx context.Context, tag string, wait time.Duration) ([]string, error) {
	groups, err := c.taggedGroups(ctx, tag)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	var deleted []string
	var errs []error
	for _, g := range groups {
		id := aws.ToString(g.GroupId)
		if err := c.deleteSecurityGroup(ctx, id, deadline); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted = append(deleted, id)
	}
	return deleted, errors.Join(errs...)
}

// deleteSecurityGroup deletes the group. A group that EC2 does not know is not an error.
func (c *Client) deleteSecurityGroup(ctx context.Context, id string, deadline time.Time) error {
	for {
		_, err := c.ec2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)})
		switch apiCode(err) {
		case "InvalidGroup.NotFound":
			return nil
		case "DependencyViolation":
			if time.Now().After(deadline) {
				return fmt.Errorf("delete security group %s: %w", id, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(deleteSecurityGroupRetry):
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("delete security group %s: %w", id, err)
		}
		return nil
	}
}

// ReapSecurityGroups deletes the security groups with the tag KEY=VALUE that no
// instance uses and whose RFC 3339 expiry tag is before now or not valid, and
// returns their IDs.
func (c *Client) ReapSecurityGroups(ctx context.Context, tag, expiryKey string, now time.Time) ([]string, error) {
	groups, err := c.taggedGroups(ctx, tag)
	if err != nil {
		return nil, err
	}
	var deleted []string
	var errs []error
	for _, g := range groups {
		if tagTime(g.Tags, expiryKey).After(now) {
			continue
		}
		id := aws.ToString(g.GroupId)
		_, err := c.ec2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)})
		switch apiCode(err) {
		case "DependencyViolation", "InvalidGroup.NotFound":
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("delete security group %s: %w", id, err))
			continue
		}
		deleted = append(deleted, id)
	}
	return deleted, errors.Join(errs...)
}

// tagTime returns the RFC 3339 time in the tag key, or the zero time.
func tagTime(tags []types.Tag, key string) time.Time {
	for _, t := range tags {
		if aws.ToString(t.Key) == key {
			if at, err := time.Parse(time.RFC3339, aws.ToString(t.Value)); err == nil {
				return at
			}
		}
	}
	return time.Time{}
}

// PublicIP returns the public IPv4 address of the instance. EC2 gives it a short
// time after the launch, so it reads again until wait ends.
func (c *Client) PublicIP(ctx context.Context, id string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		out, err := c.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
		if err != nil && apiCode(err) != "InvalidInstanceID.NotFound" {
			return "", fmt.Errorf("describe instance %s: %w", id, err)
		}
		if err == nil {
			for _, r := range out.Reservations {
				for _, i := range r.Instances {
					if ip := aws.ToString(i.PublicIpAddress); ip != "" {
						return ip, nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("instance %s has no public IP: its subnet must give one", id)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(publicIPRetry):
		}
	}
}

// Instances returns the instances with the tag KEY=VALUE that did not terminate
// yet, each as its ID and its state.
func (c *Client) Instances(ctx context.Context, tag string) ([]string, error) {
	k, v, ok := strings.Cut(tag, "=")
	if !ok || k == "" {
		return nil, fmt.Errorf("bad tag %q: want KEY=VALUE", tag)
	}
	in := &ec2.DescribeInstancesInput{Filters: []types.Filter{
		{Name: aws.String("tag:" + k), Values: []string{v}},
		{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "shutting-down", "stopping", "stopped"}},
	}}
	var found []string
	pages := ec2.NewDescribeInstancesPaginator(c.ec2, in)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				state := ""
				if i.State != nil {
					state = string(i.State.Name)
				}
				found = append(found, aws.ToString(i.InstanceId)+" "+state)
			}
		}
	}
	slices.Sort(found)
	return found, nil
}
