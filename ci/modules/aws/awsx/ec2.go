package awsx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// ErrNoCapacity tells that no subnet had capacity for the instance type.
var ErrNoCapacity = errors.New("no subnet has capacity for the instance type")

// expiryDefault is the life of an instance with no valid expiry tag, from its launch.
const expiryDefault = time.Hour

// LaunchInput describes one instance.
type LaunchInput struct {
	Image        string
	InstanceType string
	// UserData is the cloud-init user data as plain text.
	UserData string
	// Tags go on the instance and its volumes.
	Tags map[string]string
	// SubnetTag is KEY=VALUE. Launch uses the subnets and the security group
	// with this tag. When no subnet has it, Launch uses the default subnets of
	// the default VPC and its default security group.
	SubnetTag string
}

// Launch starts one instance and returns its ID. It tries the next subnet when
// a subnet has no capacity for the instance type.
func (c *Client) Launch(ctx context.Context, in LaunchInput) (string, error) {
	subnets, sg, err := c.placement(ctx, in.SubnetTag)
	if err != nil {
		return "", err
	}
	var errs []error
	for _, s := range subnets {
		id, err := c.runInstance(ctx, in, s, sg)
		if err == nil {
			return id, nil
		}
		if !capacityError(err) {
			return "", fmt.Errorf("launch in subnet %s: %w", s.id, err)
		}
		errs = append(errs, fmt.Errorf("%s (%s): %w", s.id, s.az, err))
	}
	return "", fmt.Errorf("%w: %w", ErrNoCapacity, errors.Join(errs...))
}

type subnet struct{ id, az, vpc string }

// placement returns the subnets, in AZ order, and the security group ID. An
// empty group ID means the default group of the VPC. With no tagged subnet, it
// uses the default VPC, and the tagged group of that VPC when there is one.
func (c *Client) placement(ctx context.Context, tag string) ([]subnet, string, error) {
	var tagFilter []types.Filter
	if tag != "" {
		k, v, ok := strings.Cut(tag, "=")
		if !ok || k == "" {
			return nil, "", fmt.Errorf("bad subnet tag %q: want KEY=VALUE", tag)
		}
		tagFilter = []types.Filter{{Name: aws.String("tag:" + k), Values: []string{v}}}
		subnets, err := c.subnets(ctx, tagFilter)
		if err != nil {
			return nil, "", err
		}
		if len(subnets) > 0 {
			sg, err := c.securityGroup(ctx, tagFilter)
			return subnets, sg, err
		}
	}
	subnets, err := c.subnets(ctx, []types.Filter{{Name: aws.String("default-for-az"), Values: []string{"true"}}})
	if err != nil {
		return nil, "", err
	}
	if len(subnets) == 0 {
		return nil, "", errors.New("no subnet has the tag and the region has no default subnets")
	}
	if tagFilter == nil {
		return subnets, "", nil
	}
	vpc := types.Filter{Name: aws.String("vpc-id"), Values: []string{subnets[0].vpc}}
	sg, err := c.securityGroup(ctx, append(tagFilter, vpc))
	return subnets, sg, err
}

func (c *Client) subnets(ctx context.Context, filters []types.Filter) ([]subnet, error) {
	out, err := c.ec2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{Filters: filters})
	if err != nil {
		return nil, fmt.Errorf("describe subnets: %w", err)
	}
	var s []subnet
	for _, sn := range out.Subnets {
		s = append(s, subnet{id: aws.ToString(sn.SubnetId), az: aws.ToString(sn.AvailabilityZone), vpc: aws.ToString(sn.VpcId)})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].az+s[i].id < s[j].az+s[j].id })
	return s, nil
}

// securityGroup returns the one group with the tag, or "" when no group has it.
func (c *Client) securityGroup(ctx context.Context, filters []types.Filter) (string, error) {
	out, err := c.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: filters})
	if err != nil {
		return "", fmt.Errorf("describe security groups: %w", err)
	}
	switch len(out.SecurityGroups) {
	case 0:
		return "", nil
	case 1:
		return aws.ToString(out.SecurityGroups[0].GroupId), nil
	default:
		return "", fmt.Errorf("%d security groups have the subnet tag, want one", len(out.SecurityGroups))
	}
}

func (c *Client) runInstance(ctx context.Context, in LaunchInput, s subnet, sg string) (string, error) {
	tags := ec2Tags(in.Tags)
	run := &ec2.RunInstancesInput{
		ImageId:                           aws.String(in.Image),
		InstanceType:                      types.InstanceType(in.InstanceType),
		MinCount:                          aws.Int32(1),
		MaxCount:                          aws.Int32(1),
		SubnetId:                          aws.String(s.id),
		UserData:                          aws.String(base64.StdEncoding.EncodeToString([]byte(in.UserData))),
		InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
		MetadataOptions: &types.InstanceMetadataOptionsRequest{
			HttpEndpoint:            types.InstanceMetadataEndpointStateEnabled,
			HttpTokens:              types.HttpTokensStateRequired,
			HttpPutResponseHopLimit: aws.Int32(1),
		},
		// The bench IAM policy allows tags on instances and volumes only.
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeInstance, Tags: tags},
			{ResourceType: types.ResourceTypeVolume, Tags: tags},
		},
	}
	if sg != "" {
		run.SecurityGroupIds = []string{sg}
	}
	out, err := c.ec2.RunInstances(ctx, run)
	if err != nil {
		return "", err
	}
	if len(out.Instances) != 1 {
		return "", fmt.Errorf("run instances returned %d instances, want 1", len(out.Instances))
	}
	return aws.ToString(out.Instances[0].InstanceId), nil
}

// ec2Tags returns the tags in key order.
func ec2Tags(m map[string]string) []types.Tag {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tags := make([]types.Tag, 0, len(keys))
	for _, k := range keys {
		tags = append(tags, types.Tag{Key: aws.String(k), Value: aws.String(m[k])})
	}
	return tags
}

// capacityError tells if the subnet has no capacity for the instance type, or
// its AZ does not offer the type. Another subnet can work.
func capacityError(err error) bool {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ErrorCode() {
	case "InsufficientInstanceCapacity", "Unsupported":
		return true
	}
	return false
}

// State returns the instance state, for example running or terminated. It
// returns "not-found" when EC2 does not know the instance (yet).
func (c *Client) State(ctx context.Context, id string) (string, error) {
	out, err := c.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	if apiCode(err) == "InvalidInstanceID.NotFound" {
		return "not-found", nil
	}
	if err != nil {
		return "", fmt.Errorf("describe instance %s: %w", id, err)
	}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			if i.State != nil {
				return string(i.State.Name), nil
			}
		}
	}
	return "not-found", nil
}

// Console returns the serial console output of the instance.
func (c *Client) Console(ctx context.Context, id string) (string, error) {
	out, err := c.ec2.GetConsoleOutput(ctx, &ec2.GetConsoleOutputInput{InstanceId: aws.String(id), Latest: aws.Bool(true)})
	if err != nil {
		// Latest needs a Nitro instance. Try the boot output.
		out, err = c.ec2.GetConsoleOutput(ctx, &ec2.GetConsoleOutputInput{InstanceId: aws.String(id)})
	}
	if err != nil {
		return "", fmt.Errorf("get the console output of %s: %w", id, err)
	}
	data, err := base64.StdEncoding.DecodeString(aws.ToString(out.Output))
	if err != nil {
		return "", fmt.Errorf("decode the console output of %s: %w", id, err)
	}
	return string(data), nil
}

// Terminate terminates the instances. An instance that EC2 does not know is not an error.
func (c *Client) Terminate(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := c.ec2.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: ids})
	if err != nil && apiCode(err) != "InvalidInstanceID.NotFound" {
		return fmt.Errorf("terminate %v: %w", ids, err)
	}
	return nil
}

// Reap terminates the live instances with the tag KEY=VALUE whose expiry
// (RFC 3339 in the expiry tag) is before now, or all of them when all is set.
// With no valid expiry tag, an instance expires one hour after its launch.
// Reap returns the terminated IDs.
func (c *Client) Reap(ctx context.Context, tag, expiryKey string, now time.Time, all bool) ([]string, error) {
	k, v, ok := strings.Cut(tag, "=")
	if !ok || k == "" {
		return nil, fmt.Errorf("bad tag %q: want KEY=VALUE", tag)
	}
	in := &ec2.DescribeInstancesInput{Filters: []types.Filter{
		{Name: aws.String("tag:" + k), Values: []string{v}},
		{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "stopping", "stopped"}},
	}}
	var expired []string
	pages := ec2.NewDescribeInstancesPaginator(c.ec2, in)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				if all || expiry(i, expiryKey).Before(now) {
					expired = append(expired, aws.ToString(i.InstanceId))
				}
			}
		}
	}
	return expired, c.Terminate(ctx, expired...)
}

// expiry returns the time in the expiry tag, or the launch time plus one hour.
func expiry(i types.Instance, key string) time.Time {
	for _, t := range i.Tags {
		if aws.ToString(t.Key) == key {
			if at, err := time.Parse(time.RFC3339, aws.ToString(t.Value)); err == nil {
				return at
			}
		}
	}
	return aws.ToTime(i.LaunchTime).Add(expiryDefault)
}

func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}
