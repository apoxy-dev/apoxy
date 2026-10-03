package awsx

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// fakeEC2 answers from fixed data and records the RunInstances inputs.
type fakeEC2 struct {
	tagged, defaults []types.Subnet
	groups           []types.SecurityGroup
	// full lists the subnets that answer InsufficientInstanceCapacity.
	full      map[string]bool
	runs      []*ec2.RunInstancesInput
	filters   []types.Filter
	instances []types.Instance
	ended     []string
}

func (f *fakeEC2) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if aws.ToString(in.Filters[0].Name) == "default-for-az" {
		return &ec2.DescribeSubnetsOutput{Subnets: f.defaults}, nil
	}
	return &ec2.DescribeSubnetsOutput{Subnets: f.tagged}, nil
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	groups := f.groups
	for _, flt := range in.Filters {
		if aws.ToString(flt.Name) != "vpc-id" {
			continue
		}
		groups = nil
		for _, g := range f.groups {
			if aws.ToString(g.VpcId) == flt.Values[0] {
				groups = append(groups, g)
			}
		}
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: groups}, nil
}

func (f *fakeEC2) RunInstances(_ context.Context, in *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	f.runs = append(f.runs, in)
	if f.full[aws.ToString(in.SubnetId)] {
		return nil, &smithy.GenericAPIError{Code: "InsufficientInstanceCapacity", Message: "no capacity"}
	}
	return &ec2.RunInstancesOutput{Instances: []types.Instance{{InstanceId: aws.String("i-" + aws.ToString(in.SubnetId))}}}, nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if len(in.InstanceIds) > 0 && in.InstanceIds[0] == "i-gone" {
		return nil, &smithy.GenericAPIError{Code: "InvalidInstanceID.NotFound"}
	}
	f.filters = in.Filters
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: f.instances}}}, nil
}

func (f *fakeEC2) TerminateInstances(_ context.Context, in *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	f.ended = append(f.ended, in.InstanceIds...)
	return &ec2.TerminateInstancesOutput{}, nil
}

func (f *fakeEC2) GetConsoleOutput(context.Context, *ec2.GetConsoleOutputInput, ...func(*ec2.Options)) (*ec2.GetConsoleOutputOutput, error) {
	return &ec2.GetConsoleOutputOutput{Output: aws.String(base64.StdEncoding.EncodeToString([]byte("boot log")))}, nil
}

func sn(id, az string) types.Subnet {
	return types.Subnet{SubnetId: aws.String(id), AvailabilityZone: aws.String(az), VpcId: aws.String("vpc-d")}
}

func sg(id, vpc string) types.SecurityGroup {
	return types.SecurityGroup{GroupId: aws.String(id), VpcId: aws.String(vpc)}
}

func TestLaunch(t *testing.T) {
	in := LaunchInput{
		Image: "ami-1", InstanceType: "c7a.8xlarge", UserData: "#cloud-config\n",
		Tags:      map[string]string{"apoxy-perf": "true", "apoxy-perf-run": "1-1-vpc"},
		SubnetTag: "apoxy-perf=true",
	}
	cases := []struct {
		name     string
		fake     fakeEC2
		subnetTo string
		wantID   string
		wantSG   []string
		wantRuns int
		wantErr  string
	}{
		{
			name:     "tagged subnets and group",
			fake:     fakeEC2{tagged: []types.Subnet{sn("s-b", "us-west-2b"), sn("s-a", "us-west-2a")}, groups: []types.SecurityGroup{{GroupId: aws.String("sg-1")}}},
			wantID:   "i-s-a",
			wantSG:   []string{"sg-1"},
			wantRuns: 1,
		},
		{
			name:     "next subnet on no capacity",
			fake:     fakeEC2{tagged: []types.Subnet{sn("s-a", "us-west-2a"), sn("s-b", "us-west-2b")}, full: map[string]bool{"s-a": true}},
			wantID:   "i-s-b",
			wantRuns: 2,
		},
		{
			name:     "no capacity in any subnet",
			fake:     fakeEC2{tagged: []types.Subnet{sn("s-a", "us-west-2a")}, full: map[string]bool{"s-a": true}},
			wantRuns: 1,
			wantErr:  ErrNoCapacity.Error(),
		},
		{
			name:     "default VPC when no subnet has the tag",
			fake:     fakeEC2{defaults: []types.Subnet{sn("s-d", "us-west-2c")}, groups: []types.SecurityGroup{sg("sg-other", "vpc-other")}},
			wantID:   "i-s-d",
			wantRuns: 1,
		},
		{
			name:     "tagged group in the default VPC",
			fake:     fakeEC2{defaults: []types.Subnet{sn("s-d", "us-west-2c")}, groups: []types.SecurityGroup{sg("sg-d", "vpc-d"), sg("sg-other", "vpc-other")}},
			wantID:   "i-s-d",
			wantSG:   []string{"sg-d"},
			wantRuns: 1,
		},
		{
			name:    "two tagged groups",
			fake:    fakeEC2{tagged: []types.Subnet{sn("s-a", "us-west-2a")}, groups: []types.SecurityGroup{{GroupId: aws.String("sg-1")}, {GroupId: aws.String("sg-2")}}},
			wantErr: "2 security groups",
		},
		{
			name:    "no subnets",
			fake:    fakeEC2{},
			wantErr: "no default subnets",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fake
			c := &Client{ec2: &f}
			id, err := c.Launch(context.Background(), in)
			if len(f.runs) != tc.wantRuns {
				t.Fatalf("RunInstances calls = %d, want %d", len(f.runs), tc.wantRuns)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if id != tc.wantID {
				t.Fatalf("id = %s, want %s", id, tc.wantID)
			}
			run := f.runs[len(f.runs)-1]
			if strings.Join(run.SecurityGroupIds, ",") != strings.Join(tc.wantSG, ",") {
				t.Errorf("security groups = %v, want %v", run.SecurityGroupIds, tc.wantSG)
			}
			checkRun(t, run)
		})
	}
}

// checkRun checks the parts of RunInstances that the bench IAM policy needs.
func checkRun(t *testing.T, run *ec2.RunInstancesInput) {
	t.Helper()
	if run.MetadataOptions == nil || run.MetadataOptions.HttpTokens != types.HttpTokensStateRequired {
		t.Error("IMDSv2 is not required")
	}
	if run.InstanceInitiatedShutdownBehavior != types.ShutdownBehaviorTerminate {
		t.Error("the shutdown behavior is not terminate")
	}
	var kinds []string
	for _, ts := range run.TagSpecifications {
		kinds = append(kinds, string(ts.ResourceType))
		if len(ts.Tags) != 2 || aws.ToString(ts.Tags[0].Key) != "apoxy-perf" {
			t.Errorf("tags of %s = %v", ts.ResourceType, ts.Tags)
		}
	}
	if strings.Join(kinds, ",") != "instance,volume" {
		t.Errorf("tagged resource types = %v, want instance and volume only", kinds)
	}
	data, err := base64.StdEncoding.DecodeString(aws.ToString(run.UserData))
	if err != nil || string(data) != "#cloud-config\n" {
		t.Errorf("user data = %q, %v", data, err)
	}
}

func TestReap(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	inst := func(id, expires string, launched time.Time) types.Instance {
		i := types.Instance{InstanceId: aws.String(id), LaunchTime: aws.Time(launched)}
		if expires != "" {
			i.Tags = []types.Tag{{Key: aws.String("apoxy-perf-expires"), Value: aws.String(expires)}}
		}
		return i
	}
	instances := []types.Instance{
		inst("i-expired", "2026-10-02T11:59:00Z", now.Add(-time.Hour)),
		inst("i-live", "2026-10-02T12:30:00Z", now.Add(-30*time.Minute)),
		inst("i-old-no-tag", "", now.Add(-61*time.Minute)),
		inst("i-new-bad-tag", "soon", now.Add(-10*time.Minute)),
	}
	cases := []struct {
		name      string
		instances []types.Instance
		all       bool
		want      string
	}{
		{name: "expired", instances: instances, want: "i-expired,i-old-no-tag"},
		{name: "all", instances: instances, all: true, want: "i-expired,i-live,i-old-no-tag,i-new-bad-tag"},
		{name: "none left", all: true, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEC2{instances: tc.instances}
			c := &Client{ec2: f}
			got, err := c.Reap(context.Background(), "apoxy-perf-run=1-1-vpc", "apoxy-perf-expires", now, tc.all)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != tc.want || strings.Join(f.ended, ",") != tc.want {
				t.Fatalf("reaped %v, terminated %v, want %s", got, f.ended, tc.want)
			}
			if tag := f.filters[0]; aws.ToString(tag.Name) != "tag:apoxy-perf-run" || tag.Values[0] != "1-1-vpc" {
				t.Errorf("tag filter = %s %v", aws.ToString(tag.Name), tag.Values)
			}
		})
	}
}

func TestStateAndConsole(t *testing.T) {
	f := &fakeEC2{instances: []types.Instance{{InstanceId: aws.String("i-1"), State: &types.InstanceState{Name: types.InstanceStateNameRunning}}}}
	c := &Client{ec2: f}
	cases := []struct{ id, want string }{
		{"i-1", "running"},
		{"i-gone", "not-found"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got, err := c.State(context.Background(), tc.id)
			if err != nil || got != tc.want {
				t.Fatalf("State = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
	out, err := c.Console(context.Background(), "i-1")
	if err != nil || out != "boot log" {
		t.Fatalf("Console = %q, %v", out, err)
	}
}

func TestCapacityError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"capacity", &smithy.GenericAPIError{Code: "InsufficientInstanceCapacity"}, true},
		{"AZ without the type", &smithy.GenericAPIError{Code: "Unsupported"}, true},
		{"denied", &smithy.GenericAPIError{Code: "UnauthorizedOperation"}, false},
		{"not an API error", errors.New("dial tcp: timeout"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := capacityError(tc.err); got != tc.want {
				t.Fatalf("capacityError = %v, want %v", got, tc.want)
			}
		})
	}
}
