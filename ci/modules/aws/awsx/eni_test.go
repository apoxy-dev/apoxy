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

func TestAttachNewInterface(t *testing.T) {
	defer func(d time.Duration) { interfaceRetry = d }(interfaceRetry)
	interfaceRetry = time.Millisecond
	running := func(state types.InstanceStateName) []types.Instance {
		return []types.Instance{{
			InstanceId: aws.String("i-1"), SubnetId: aws.String("s-a"), State: &types.InstanceState{Name: state},
			SecurityGroups: []types.GroupIdentifier{{GroupId: aws.String("sg-1")}, {GroupId: aws.String("sg-2")}},
		}}
	}
	tags := map[string]string{"apoxy-perf": "true", "apoxy-perf-run": "1-1-vpc"}
	cases := []struct {
		name    string
		fake    fakeEC2
		wait    time.Duration
		wantErr string
	}{
		{name: "running", fake: fakeEC2{instances: running(types.InstanceStateNameRunning)}},
		{name: "pending, then running", fake: fakeEC2{instances: running(types.InstanceStateNameRunning), pending: 2}, wait: time.Minute},
		{name: "pending until the wait ends", fake: fakeEC2{instances: running(types.InstanceStateNameRunning), pending: 1000}, wait: 10 * time.Millisecond, wantErr: "is pending after"},
		{name: "terminated", fake: fakeEC2{instances: running(types.InstanceStateNameTerminated)}, wantErr: "is terminated, not running"},
		{name: "attach fails", fake: fakeEC2{instances: running(types.InstanceStateNameRunning), failAttach: true}, wantErr: "attach network interface eni-1"},
		{name: "modify fails", fake: fakeEC2{instances: running(types.InstanceStateNameRunning), failModify: true}, wantErr: "set network interface eni-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fake
			c := &Client{ec2: &f}
			id, err := c.AttachNewInterface(context.Background(), "i-1", tags, tc.wait)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if len(f.enis) != 0 {
					t.Fatalf("interfaces left after the failure: %v", slices.Collect(func(yield func(string) bool) {
						for k := range f.enis {
							yield(k)
						}
					}))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e := f.enis[id]
			if e == nil || aws.ToString(e.SubnetId) != "s-a" || len(e.Groups) != 2 || aws.ToString(e.Groups[1].GroupId) != "sg-2" {
				t.Fatalf("interface = %+v, want subnet s-a and groups sg-1, sg-2", e)
			}
			if len(e.TagSet) != 2 || aws.ToString(e.TagSet[0].Key) != "apoxy-perf" {
				t.Errorf("tags = %v", e.TagSet)
			}
			a := e.Attachment
			if a == nil || aws.ToString(a.InstanceId) != "i-1" || aws.ToInt32(a.DeviceIndex) != 1 || !aws.ToBool(a.DeleteOnTermination) {
				t.Errorf("attachment = %+v, want i-1 at device index 1 with delete on termination", a)
			}
		})
	}
}

func TestDeleteNetworkInterfaces(t *testing.T) {
	defer func(d time.Duration) { interfaceRetry = d }(interfaceRetry)
	interfaceRetry = time.Millisecond
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	eni := func(id, run, expires string, status types.NetworkInterfaceStatus) *types.NetworkInterface {
		tags := []types.Tag{{Key: aws.String("apoxy-perf"), Value: aws.String("true")}, {Key: aws.String("apoxy-perf-run"), Value: aws.String(run)}}
		if expires != "" {
			tags = append(tags, types.Tag{Key: aws.String("apoxy-perf-expires"), Value: aws.String(expires)})
		}
		return &types.NetworkInterface{NetworkInterfaceId: aws.String(id), Status: status, TagSet: tags}
	}
	fake := func() *fakeEC2 {
		return &fakeEC2{enis: map[string]*types.NetworkInterface{
			"eni-a1":  eni("eni-a1", "run-a", "2026-10-22T11:00:00Z", types.NetworkInterfaceStatusAvailable),
			"eni-a2":  eni("eni-a2", "run-a", "2026-10-22T11:00:00Z", types.NetworkInterfaceStatusInUse),
			"eni-b":   eni("eni-b", "run-b", "2026-10-22T13:00:00Z", types.NetworkInterfaceStatusAvailable),
			"eni-old": eni("eni-old", "run-c", "", types.NetworkInterfaceStatusAvailable),
		}, eniInUse: map[string]int{"eni-a2": 2}}
	}
	cases := []struct {
		name     string
		reap     bool
		tag      string
		wait     time.Duration
		want     []string
		wantLeft []string
		wantErr  string
	}{
		{name: "the interfaces of one run, after the instance ends", tag: "apoxy-perf-run=run-a", wait: time.Minute,
			want: []string{"eni-a1", "eni-a2"}, wantLeft: []string{"eni-b", "eni-old"}},
		{name: "an attached interface with no wait", tag: "apoxy-perf-run=run-a",
			want: []string{"eni-a1"}, wantLeft: []string{"eni-a2", "eni-b", "eni-old"}, wantErr: "currently in use"},
		{name: "a run with none", tag: "apoxy-perf-run=run-x", wantLeft: []string{"eni-a1", "eni-a2", "eni-b", "eni-old"}},
		{name: "bad tag", tag: "apoxy-perf", wantErr: "want KEY=VALUE", wantLeft: []string{"eni-a1", "eni-a2", "eni-b", "eni-old"}},
		{name: "reap the expired available interfaces", reap: true, tag: "apoxy-perf=true",
			want: []string{"eni-a1", "eni-old"}, wantLeft: []string{"eni-a2", "eni-b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake()
			c := &Client{ec2: f}
			var got []string
			var err error
			if tc.reap {
				got, err = c.ReapNetworkInterfaces(context.Background(), tc.tag, "apoxy-perf-expires", now)
			} else {
				got, err = c.DeleteNetworkInterfaces(context.Background(), tc.tag, tc.wait)
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			slices.Sort(got)
			left, lerr := c.NetworkInterfaces(context.Background(), "apoxy-perf=true")
			if lerr != nil {
				t.Fatal(lerr)
			}
			for i, l := range left {
				left[i], _, _ = strings.Cut(l, " ")
			}
			if !slices.Equal(got, tc.want) || !slices.Equal(left, tc.wantLeft) {
				t.Fatalf("deleted %v, left %v, want %v and %v", got, left, tc.want, tc.wantLeft)
			}
		})
	}
}
