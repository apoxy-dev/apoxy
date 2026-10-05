package awsx

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
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
	// placements are the placement groups, groupTags their tags, and inUse
	// answers InUse for a name n times.
	placements []string
	groupTags  map[string][]types.Tag
	inUse      map[string]int
	created    []*ec2.CreatePlacementGroupInput
	// notFound answers NotFound to DescribeInstances this many times.
	notFound int
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
	if f.notFound > 0 {
		f.notFound--
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

func (f *fakeEC2) CreatePlacementGroup(_ context.Context, in *ec2.CreatePlacementGroupInput, _ ...func(*ec2.Options)) (*ec2.CreatePlacementGroupOutput, error) {
	f.created = append(f.created, in)
	if slices.Contains(f.placements, aws.ToString(in.GroupName)) {
		return nil, &smithy.GenericAPIError{Code: "InvalidPlacementGroup.Duplicate"}
	}
	f.placements = append(f.placements, aws.ToString(in.GroupName))
	if f.groupTags == nil {
		f.groupTags = map[string][]types.Tag{}
	}
	for _, ts := range in.TagSpecifications {
		f.groupTags[aws.ToString(in.GroupName)] = append(f.groupTags[aws.ToString(in.GroupName)], ts.Tags...)
	}
	return &ec2.CreatePlacementGroupOutput{}, nil
}

func (f *fakeEC2) DeletePlacementGroup(_ context.Context, in *ec2.DeletePlacementGroupInput, _ ...func(*ec2.Options)) (*ec2.DeletePlacementGroupOutput, error) {
	name := aws.ToString(in.GroupName)
	if !slices.Contains(f.placements, name) {
		return nil, &smithy.GenericAPIError{Code: "InvalidPlacementGroup.Unknown"}
	}
	if f.inUse[name] > 0 {
		f.inUse[name]--
		return nil, &smithy.GenericAPIError{Code: "InvalidPlacementGroup.InUse"}
	}
	f.placements = slices.DeleteFunc(f.placements, func(g string) bool { return g == name })
	return &ec2.DeletePlacementGroupOutput{}, nil
}

// DescribePlacementGroups returns the groups that have each tag of the filters.
func (f *fakeEC2) DescribePlacementGroups(_ context.Context, in *ec2.DescribePlacementGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribePlacementGroupsOutput, error) {
	var out ec2.DescribePlacementGroupsOutput
	for _, g := range f.placements {
		match := func(fl types.Filter) bool {
			return slices.ContainsFunc(f.groupTags[g], func(t types.Tag) bool {
				return "tag:"+aws.ToString(t.Key) == aws.ToString(fl.Name) && slices.Contains(fl.Values, aws.ToString(t.Value))
			})
		}
		if !slices.ContainsFunc(in.Filters, func(fl types.Filter) bool { return !match(fl) }) {
			out.PlacementGroups = append(out.PlacementGroups, types.PlacementGroup{GroupName: aws.String(g), State: types.PlacementGroupStateAvailable, Tags: f.groupTags[g]})
		}
	}
	return &out, nil
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
		{
			name:     "fixed subnet in a placement group",
			fake:     fakeEC2{tagged: []types.Subnet{sn("s-a", "us-west-2a"), sn("s-b", "us-west-2b")}},
			subnetTo: "s-b",
			wantID:   "i-s-b",
			wantRuns: 1,
		},
		{
			name:     "fixed subnet with no capacity",
			fake:     fakeEC2{tagged: []types.Subnet{sn("s-a", "us-west-2a"), sn("s-b", "us-west-2b")}, full: map[string]bool{"s-b": true}},
			subnetTo: "s-b",
			wantRuns: 1,
			wantErr:  ErrNoCapacity.Error(),
		},
		{
			name:     "fixed subnet that is not a bench subnet",
			fake:     fakeEC2{tagged: []types.Subnet{sn("s-a", "us-west-2a")}},
			subnetTo: "s-x",
			wantErr:  "not a bench subnet",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fake
			c := &Client{ec2: &f}
			in := in
			if tc.subnetTo != "" {
				in.Subnet, in.PlacementGroup = tc.subnetTo, "apoxy-perf-1-1-vpc"
			}
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
			if tc.subnetTo != "" && (run.Placement == nil || aws.ToString(run.Placement.GroupName) != in.PlacementGroup) {
				t.Errorf("placement = %+v, want group %s", run.Placement, in.PlacementGroup)
			}
			if tc.subnetTo == "" && run.Placement != nil {
				t.Errorf("placement = %+v, want none", run.Placement)
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

func TestFacts(t *testing.T) {
	f := &fakeEC2{notFound: 2, instances: []types.Instance{{
		InstanceId: aws.String("i-1"), PrivateIpAddress: aws.String("10.0.1.5"), SubnetId: aws.String("s-a"),
		State: &types.InstanceState{Name: types.InstanceStateNamePending}, Placement: &types.Placement{AvailabilityZone: aws.String("us-west-2a")},
	}}}
	c := &Client{ec2: f}
	got, err := c.Facts(context.Background(), "i-1")
	if err != nil {
		t.Fatal(err)
	}
	want := InstanceFacts{State: "pending", PrivateIP: "10.0.1.5", SubnetID: "s-a", AZ: "us-west-2a"}
	if got != want {
		t.Fatalf("Facts = %+v, want %+v", got, want)
	}
	if _, err := c.Facts(context.Background(), "i-gone"); err == nil {
		t.Fatal("Facts of an unknown instance passed")
	}
}

func TestPlacementGroups(t *testing.T) {
	defer func(d time.Duration) { deleteGroupRetry = d }(deleteGroupRetry)
	deleteGroupRetry = time.Millisecond
	ctx := context.Background()
	f := &fakeEC2{inUse: map[string]int{"pg-busy": 1}}
	c := &Client{ec2: f}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tags := map[string]string{"apoxy-perf": "true", "apoxy-perf-run": "1-1-vpc", "apoxy-perf-expires": "2026-10-03T11:00:00Z"}
	if err := c.CreatePlacementGroup(ctx, "pg-a", tags); err != nil {
		t.Fatal(err)
	}
	if err := c.CreatePlacementGroup(ctx, "pg-a", tags); err != nil {
		t.Fatalf("a second create of the same group failed: %v", err)
	}
	if ts := f.created[0].TagSpecifications; f.created[0].Strategy != types.PlacementStrategyCluster || len(ts) != 1 || ts[0].ResourceType != types.ResourceTypePlacementGroup || len(ts[0].Tags) != 3 {
		t.Errorf("create = %+v", f.created[0])
	}
	if err := c.CreatePlacementGroup(ctx, "pg-busy", tags); err != nil {
		t.Fatal(err)
	}
	// The busy group answers InUse one time, then the delete passes.
	if err := c.DeletePlacementGroup(ctx, "pg-busy", 0); err == nil || !strings.Contains(err.Error(), "InUse") {
		t.Fatalf("delete of a busy group with no wait = %v, want InUse", err)
	}
	if err := c.DeletePlacementGroup(ctx, "pg-busy", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePlacementGroup(ctx, "pg-unknown", 0); err != nil {
		t.Fatalf("delete of an unknown group = %v", err)
	}
	// pg-a is in use, pg-new did not expire, pg-free and pg-untagged are free.
	f.inUse["pg-a"] = 1
	for name, expires := range map[string]string{"pg-free": "2026-10-03T11:00:00Z", "pg-new": "2026-10-03T13:00:00Z", "pg-untagged": ""} {
		tg := map[string]string{"apoxy-perf": "true"}
		if expires != "" {
			tg["apoxy-perf-expires"] = expires
		}
		if err := c.CreatePlacementGroup(ctx, name, tg); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		tag  string
		want []string
	}{
		{"apoxy-perf-run=1-1-vpc", []string{"pg-a available"}},
		{"apoxy-perf=true", []string{"pg-a available", "pg-free available", "pg-new available", "pg-untagged available"}},
		{"apoxy-perf-run=other", []string{}},
	} {
		if got, err := c.PlacementGroups(ctx, tc.tag); err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("groups with %s = %v, %v, want %v", tc.tag, got, err, tc.want)
		}
	}
	if _, err := c.PlacementGroups(ctx, "no-value"); err == nil {
		t.Error("a tag with no value passed")
	}
	got, err := c.ReapPlacementGroups(ctx, "apoxy-perf=true", "apoxy-perf-expires", now)
	slices.Sort(got)
	slices.Sort(f.placements)
	if err != nil || !slices.Equal(got, []string{"pg-free", "pg-untagged"}) || !slices.Equal(f.placements, []string{"pg-a", "pg-new"}) {
		t.Fatalf("reap = %v, %v, groups left %v", got, err, f.placements)
	}
}
