package awsx

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestSecurityGroups(t *testing.T) {
	defer func(d time.Duration) { deleteSecurityGroupRetry = d }(deleteSecurityGroupRetry)
	deleteSecurityGroupRetry = time.Millisecond
	ctx := context.Background()
	f := &fakeEC2{defaults: []types.Subnet{sn("s-d", "us-east-1a")}, groups: []types.SecurityGroup{sg("sg-bench", "vpc-d")}}
	c := &Client{ec2: f}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	tags := func(run, expires string) map[string]string {
		return map[string]string{"apoxy-perf-group": "true", "apoxy-perf-run": run, "apoxy-perf-expires": expires}
	}

	// The group goes into the VPC of the bench subnets, and its members can send to each other.
	id, err := c.CreateSecurityGroup(ctx, "apoxy-perf-1-1-vpc", "apoxy-perf=true", tags("1-1-vpc", "2026-10-11T11:00:00Z"))
	if err != nil || id != "sg-apoxy-perf-1-1-vpc" {
		t.Fatalf("create = %q, %v", id, err)
	}
	if g := f.made[0]; aws.ToString(g.VpcId) != "vpc-d" || len(g.Tags) != 3 {
		t.Errorf("group = %+v", g)
	}
	if r := f.rules[id]; len(r) != 1 || aws.ToString(r[0].IpProtocol) != "-1" || len(r[0].UserIdGroupPairs) != 1 || aws.ToString(r[0].UserIdGroupPairs[0].GroupId) != id {
		t.Errorf("rules after create = %+v", r)
	}
	if again, err := c.CreateSecurityGroup(ctx, "apoxy-perf-1-1-vpc", "apoxy-perf=true", tags("1-1-vpc", "")); err != nil || again != id {
		t.Fatalf("a second create of the same group = %q, %v, want %q", again, err, id)
	}

	if err := c.AllowFrom(ctx, id, nil); err != nil || len(f.rules[id]) != 1 {
		t.Fatalf("AllowFrom with no address = %v, rules %+v", err, f.rules[id])
	}
	if err := c.AllowFrom(ctx, id, []string{"198.51.100.7/32", "198.51.100.8/32"}); err != nil {
		t.Fatal(err)
	}
	if r := f.rules[id][1]; aws.ToString(r.IpProtocol) != "-1" || len(r.IpRanges) != 2 || aws.ToString(r.IpRanges[1].CidrIp) != "198.51.100.8/32" {
		t.Errorf("rule of AllowFrom = %+v", r)
	}

	// A launch with the group of the run does not use the group of the bench subnets.
	in := LaunchInput{Image: "ami-1", InstanceType: "c7a.8xlarge", SubnetTag: "apoxy-perf=true", SecurityGroup: id}
	if _, err := c.Launch(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got := f.runs[0].SecurityGroupIds; !slices.Equal(got, []string{id}) {
		t.Errorf("security groups of the launch = %v, want %s", got, id)
	}

	for _, run := range []string{"2-1-vpc", "3-1-vpc"} {
		if _, err := c.CreateSecurityGroup(ctx, "apoxy-perf-"+run, "apoxy-perf=true", tags(run, "2026-10-11T13:00:00Z")); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		tag  string
		want []string
	}{
		{"apoxy-perf-run=1-1-vpc", []string{"sg-apoxy-perf-1-1-vpc apoxy-perf-1-1-vpc"}},
		{"apoxy-perf-group=true", []string{"sg-apoxy-perf-1-1-vpc apoxy-perf-1-1-vpc", "sg-apoxy-perf-2-1-vpc apoxy-perf-2-1-vpc", "sg-apoxy-perf-3-1-vpc apoxy-perf-3-1-vpc"}},
		{"apoxy-perf-run=other", []string{}},
	}
	for _, tc := range cases {
		if got, err := c.SecurityGroups(ctx, tc.tag); err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("groups with %s = %v, %v, want %v", tc.tag, got, err, tc.want)
		}
	}
	if _, err := c.SecurityGroups(ctx, "no-value"); err == nil {
		t.Error("a tag with no value passed")
	}

	// An instance uses the group of run 2 for one try.
	f.sgInUse = map[string]int{"sg-apoxy-perf-2-1-vpc": 1}
	if _, err := c.DeleteSecurityGroups(ctx, "apoxy-perf-run=2-1-vpc", 0); err == nil || !strings.Contains(err.Error(), "DependencyViolation") {
		t.Fatalf("delete of a group in use with no wait = %v, want DependencyViolation", err)
	}
	f.sgInUse["sg-apoxy-perf-2-1-vpc"] = 1
	if got, err := c.DeleteSecurityGroups(ctx, "apoxy-perf-run=2-1-vpc", time.Minute); err != nil || !slices.Equal(got, []string{"sg-apoxy-perf-2-1-vpc"}) {
		t.Fatalf("delete with a wait = %v, %v", got, err)
	}
	if got, err := c.DeleteSecurityGroups(ctx, "apoxy-perf-run=2-1-vpc", 0); err != nil || len(got) != 0 {
		t.Fatalf("a second delete = %v, %v, want nothing", got, err)
	}

	// The group of run 1 expired. The group of run 3 did not.
	got, err := c.ReapSecurityGroups(ctx, "apoxy-perf-group=true", "apoxy-perf-expires", now)
	if err != nil || !slices.Equal(got, []string{"sg-apoxy-perf-1-1-vpc"}) || len(f.made) != 1 || aws.ToString(f.made[0].GroupName) != "apoxy-perf-3-1-vpc" {
		t.Fatalf("reap = %v, %v, groups left %+v", got, err, f.made)
	}
}

func TestPublicIP(t *testing.T) {
	defer func(d time.Duration) { publicIPRetry = d }(publicIPRetry)
	publicIPRetry = time.Millisecond
	cases := []struct {
		name string
		// misses is the number of reads with no public IP.
		misses  int
		wait    time.Duration
		want    string
		wantErr string
	}{
		{name: "at the first read", wait: time.Minute, want: "198.51.100.7"},
		{name: "after two reads", misses: 2, wait: time.Minute, want: "198.51.100.7"},
		{name: "none in time", misses: 1000, wait: 5 * time.Millisecond, wantErr: "has no public IP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEC2{noPublicIP: tc.misses, instances: []types.Instance{{InstanceId: aws.String("i-1"), PublicIpAddress: aws.String("198.51.100.7")}}}
			c := &Client{ec2: f}
			got, err := c.PublicIP(context.Background(), "i-1", tc.wait)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("PublicIP = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestInstances(t *testing.T) {
	f := &fakeEC2{instances: []types.Instance{
		{InstanceId: aws.String("i-2"), State: &types.InstanceState{Name: types.InstanceStateNameShuttingDown}},
		{InstanceId: aws.String("i-1"), State: &types.InstanceState{Name: types.InstanceStateNameRunning}},
	}}
	c := &Client{ec2: f}
	got, err := c.Instances(context.Background(), "apoxy-perf-run=1-1-vpc")
	if err != nil || !slices.Equal(got, []string{"i-1 running", "i-2 shutting-down"}) {
		t.Fatalf("Instances = %v, %v", got, err)
	}
	// A terminated instance is not in the list: the filter has all other states.
	if len(f.filters) != 2 || aws.ToString(f.filters[0].Name) != "tag:apoxy-perf-run" || slices.Contains(f.filters[1].Values, "terminated") || !slices.Contains(f.filters[1].Values, "shutting-down") {
		t.Errorf("filters = %+v", f.filters)
	}
	if _, err := c.Instances(context.Background(), "no-value"); err == nil {
		t.Error("a tag with no value passed")
	}
}
