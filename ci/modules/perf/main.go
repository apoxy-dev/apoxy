// Module perf runs perf rows with perfagent (cmd/perfagent), on new EC2
// instances or in a privileged container on the engine host. All return the
// same directory: agent.json, agent.log, results/, logs/ and work/, and
// console.txt when the instance failed. An infra failure is not an error of
// the function: agent.json then has infra_error.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"dagger/perf/internal/dagger"
	"dagger/perf/perfspec"
)

const (
	// Ubuntu 24.04 amd64 server, 20260904, us-west-2 (Canonical).
	defaultImage = "ami-04678417fc39d7171"
	// rigImage has iperf3 3.19 (perfrig needs 3.16 or later), iproute2, iputils ping and ethtool.
	rigImage = "alpine:3.22"
	// poweroff is the life of an instance. A systemd timer powers it off and
	// the reaper terminates it after this time.
	poweroff = 60 * time.Minute
	// uploadSlack is the time after the deadline for the uploads of perfagent.
	uploadSlack = 8 * time.Minute
	pollEvery   = 20 * time.Second
	// nodeGrace is the time that the server and the relay hosts get to put their
	// outputs after the client host is done.
	nodeGrace = 3 * time.Minute
	// groupDeleteWait is the time to wait for the instances of a placement group to terminate.
	groupDeleteWait = "4m"
	// publicIPWait is the time to wait for the public IP of a new host.
	publicIPWait = "2m"
)

type Perf struct{}

// Local runs the plan with perfagent in a privileged container on the engine host.
func (m *Perf) Local(
	ctx context.Context,
	// perfagent and the binaries of the rows, for the engine platform.
	bins *dagger.Directory,
	// Files for the run directory, for example baseline.json.
	// +optional
	files *dagger.Directory,
	// The rows and the host setup, as a perfagent spec in JSON with no run_id,
	// deadline, bins, files or upload.
	plan string,
	// Time for the rows.
	// +default="40m"
	deadline string,
) (*dagger.Directory, error) {
	spec, d, err := parse(plan, deadline)
	if err != nil {
		return nil, err
	}
	spec.RunID = "local"
	spec.Deadline = time.Now().Add(d).UTC()
	if spec.Bins, err = hashAll(ctx, bins, true); err != nil {
		return nil, err
	}
	if files != nil {
		if spec.Files, err = hashAll(ctx, files, false); err != nil {
			return nil, err
		}
	}
	js, err := spec.JSON()
	if err != nil {
		return nil, err
	}
	ctr := dag.Container().From(rigImage).
		WithExec([]string{"apk", "add", "--no-cache", "iperf3", "iproute2", "iputils-ping", "ethtool"}).
		WithDirectory("/perf/bin", bins).
		WithNewFile("/perf/spec.json", js)
	if files != nil {
		ctr = ctr.WithDirectory("/perf/run", files)
	}
	ctr = ctr.WithExec(
		[]string{"/perf/bin/" + perfspec.Agent, "-root", "/perf", "-out", "/out", "-spec", "/perf/spec.json"},
		dagger.ContainerWithExecOpts{InsecureRootCapabilities: true, Expect: dagger.ReturnTypeAny})
	code, err := ctr.ExitCode(ctx)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		stderr, _ := ctr.Stderr(ctx)
		return infra(spec.RunID, fmt.Errorf("perfagent exited with code %d: %s", code, tail(stderr, 20))), nil
	}
	out := ctr.Directory("/out")
	var results *dagger.File
	if has(ctx, out, "results.tgz") {
		results = out.File("results.tgz")
	}
	return collect(ctx, out.File("agent.json"), out.File("agent.log"), results)
}

// Ec2 runs the plan on a new EC2 instance. It puts the binaries, the files and
// the spec in S3 under runs/RUN_TAG/in/, launches the instance with cloud-init
// user data that starts perfagent, and waits for runs/RUN_TAG/out/agent.json.
// It then terminates the instance and deletes the inputs. It terminates
// expired bench instances at the start and at the end.
func (m *Perf) Ec2(
	ctx context.Context,
	// perfagent and the binaries of the rows, for linux/amd64.
	bins *dagger.Directory,
	// Files for the run directory, for example baseline.json.
	// +optional
	files *dagger.Directory,
	// The rows and the host setup, as a perfagent spec in JSON with no run_id,
	// deadline, bins, files or upload.
	plan string,
	// Names the run in the S3 keys and the tags, for example RUN_ID-ATTEMPT-JOB.
	runTag string,
	bucket string,
	// +default="us-west-2"
	region string,
	accessKeyId *dagger.Secret,
	secretAccessKey *dagger.Secret,
	// +optional
	sessionToken *dagger.Secret,
	// Time for the rows, from the launch. The presigned URLs expire 10m after
	// it, or when the session ends.
	// +default="25m"
	deadline string,
	// +default="ami-04678417fc39d7171"
	image string,
	// +default="c7a.8xlarge"
	instanceType string,
	// KEY=VALUE tag of the subnets and the security group. With no tagged
	// subnet, the instance goes into the default VPC, with the tagged group
	// of that VPC, else its default group.
	// +default="apoxy-perf=true"
	subnetTag string,
	// Replaces the AWS endpoints, for example with a local AWS fake.
	// +optional
	endpoint string,
) (*dagger.Directory, error) {
	spec, d, err := parse(plan, deadline)
	if err != nil {
		return nil, err
	}
	keys, err := perfspec.NewKeys(runTag)
	if err != nil {
		return nil, err
	}
	if d+uploadSlack >= poweroff {
		return nil, fmt.Errorf("deadline %s plus %s is not less than the instance life %s", d, uploadSlack, poweroff)
	}
	spec.RunID = runTag
	r := newEC2Run(region, accessKeyId, secretAccessKey, sessionToken, endpoint, bucket, runTag, keys, d)
	reap(ctx, r.aws)
	defer reap(context.WithoutCancel(ctx), r.aws)
	// The inputs have presigned URLs. Delete them in all cases.
	defer r.cleanup(context.WithoutCancel(ctx))

	agentURL, err := r.inputs(ctx, &spec, bins, files)
	if err == nil {
		err = r.uploads(ctx, &spec, keys.Output)
	}
	if err != nil {
		return infra(runTag, err), nil
	}
	launched := time.Now()
	spec.Deadline = launched.Add(d).UTC()
	id, err := r.launch(ctx, r.aws, spec, keys.Spec(), agentURL, launchOpts{image: image, instanceType: instanceType, subnetTag: subnetTag}, launched)
	if err != nil {
		return infra(runTag, err), nil
	}
	inst := r.aws.Instance(id)
	defer r.terminate(context.WithoutCancel(ctx), inst, id)
	slog.Info("Launched the bench instance", "instance", id, "deadline", spec.Deadline)

	if err := r.wait(ctx, inst, keys.Output("agent.json"), spec.Deadline.Add(uploadSlack)); err != nil {
		return r.failed(ctx, inst, err), nil
	}
	dir, err := r.collect(ctx, keys.Output)
	if err != nil {
		return infra(runTag, fmt.Errorf("get the outputs: %w", err)), nil
	}
	return dir, nil
}

// Ec2Nodes runs the plan of each role on its own host in one cluster placement
// group. The client host outputs are at the top, the others under nodes/ROLE/.
// With a second relay, the second relay and the server are in peerRegion, in
// their own placement group, and the hosts of the two regions use their public
// IPs between them.
func (m *Perf) Ec2Nodes(
	ctx context.Context,
	// perfagent and the binaries of the rows, for linux/amd64.
	bins *dagger.Directory,
	// Files for the run directory, for example baseline.json.
	// +optional
	files *dagger.Directory,
	// A JSON object with a plan for each role: client, server, relay (optional)
	// and relay2 (optional).
	plans string,
	// Names the run in the S3 keys, the tags, the placement groups and the security groups.
	runTag string,
	bucket string,
	// +default="us-west-2"
	region string,
	accessKeyId *dagger.Secret,
	secretAccessKey *dagger.Secret,
	// +optional
	sessionToken *dagger.Secret,
	// Time for the rows, from the launch of the first host.
	// +default="25m"
	deadline string,
	// +default="ami-04678417fc39d7171"
	image string,
	// +default="c7a.8xlarge"
	instanceType string,
	// KEY=VALUE tag of the subnets and the security group.
	// +default="apoxy-perf=true"
	subnetTag string,
	// Replaces the AWS endpoints, for example with a local AWS fake.
	// +optional
	endpoint string,
	// The region of the second relay and the server. Plans with relay2 need it.
	// +optional
	peerRegion string,
	// The image of the hosts in peerRegion: the same OS as image.
	// +optional
	peerImage string,
) (*dagger.Directory, error) {
	specs, err := perfspec.ParseNodePlans(plans)
	if err != nil {
		return nil, err
	}
	d, err := time.ParseDuration(deadline)
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("bad deadline %q", deadline)
	}
	keys, err := perfspec.NewKeys(runTag)
	if err != nil {
		return nil, err
	}
	if d+uploadSlack >= poweroff {
		return nil, fmt.Errorf("deadline %s plus %s is not less than the instance life %s", d, uploadSlack, poweroff)
	}
	_, two := specs["relay2"]
	if two && (peerRegion == "" || peerRegion == region || peerImage == "") {
		return nil, errors.New("plans with a second relay need a peer region that is not the region, and a peer image")
	}
	r := newEC2Run(region, accessKeyId, secretAccessKey, sessionToken, endpoint, bucket, runTag, keys, d)
	home := &site{aws: r.aws, region: region, image: image}
	sites := []*site{home}
	siteOf := func(string) *site { return home }
	if two {
		peer := &site{aws: awsIn(peerRegion, accessKeyId, secretAccessKey, sessionToken, endpoint), region: peerRegion, image: peerImage}
		sites = append(sites, peer)
		siteOf = func(role string) *site {
			if slices.Contains(perfspec.PeerRoles, role) {
				return peer
			}
			return home
		}
	}
	for _, st := range sites {
		reap(ctx, st.aws)
		defer reap(context.WithoutCancel(ctx), st.aws)
	}
	defer r.cleanup(context.WithoutCancel(ctx))
	group := perfspec.GroupName(runTag)
	// The deferred terminates run first, so the groups are free when these run.
	for _, st := range sites {
		defer deleteGroup(context.WithoutCancel(ctx), st.aws, group)
		if two {
			defer deleteSecurityGroups(context.WithoutCancel(ctx), st, runTag)
		}
	}

	// The bins and the files are the same for all hosts.
	var shared perfspec.Spec
	agentURL, err := r.inputs(ctx, &shared, bins, files)
	if err != nil {
		return infra(runTag, err), nil
	}
	launched := time.Now()
	deadlineAt := launched.Add(d).UTC()
	for _, st := range sites {
		if err := st.aws.CreatePlacementGroup(ctx, group, perfspec.Tags(runTag, launched.Add(poweroff))); err != nil {
			return infra(runTag, fmt.Errorf("%s: %w", st.region, err)), nil
		}
		if !two {
			continue
		}
		// The security group of the bench subnets does not take the hosts of another region.
		opts := dagger.AwsCreateSecurityGroupOpts{SubnetTag: subnetTag}
		if st.securityGroup, err = st.aws.CreateSecurityGroup(ctx, group, perfspec.SecurityGroupTags(runTag, launched.Add(poweroff)), opts); err != nil {
			return infra(runTag, fmt.Errorf("%s: %w", st.region, err)), nil
		}
	}
	hosts := map[string]host{}
	insts := map[string]*dagger.AwsInstance{}
	for _, role := range perfspec.NodeRoles {
		spec, ok := specs[role]
		if !ok {
			continue
		}
		st := siteOf(role)
		spec.RunID, spec.Deadline, spec.Bins, spec.Files = runTag, deadlineAt, shared.Bins, shared.Files
		spec.Nodes = nodeAddrs(hosts, st)
		if err := r.uploads(ctx, &spec, func(name string) string { return keys.NodeOutput(role, name) }); err != nil {
			return infra(runTag, err), nil
		}
		opts := launchOpts{image: st.image, instanceType: instanceType, subnetTag: subnetTag, subnet: st.subnet, group: group, securityGroup: st.securityGroup}
		id, err := r.launch(ctx, st.aws, spec, keys.NodeSpec(role), agentURL, opts, launched)
		if err != nil {
			return infra(runTag, fmt.Errorf("launch the %s host in %s: %w", role, st.region, err)), nil
		}
		inst := st.aws.Instance(id)
		insts[role] = inst
		defer r.terminate(context.WithoutCancel(ctx), inst, id)
		facts := inst.Facts()
		h := host{site: st}
		if h.private, err = facts.PrivateIP(ctx); err == nil {
			st.subnet, err = facts.SubnetID(ctx)
		}
		if err == nil && two {
			h.public, err = inst.PublicIP(ctx, publicIPWait)
		}
		if err != nil {
			return infra(runTag, fmt.Errorf("read the facts of the %s host: %w", role, err)), nil
		}
		hosts[role] = h
		slog.Info("Launched a bench host", "role", role, "region", st.region, "instance", id, "ip", h.private, "public_ip", h.public,
			"subnet", st.subnet, "group", group, "deadline", deadlineAt)
	}
	// The hosts wait for each other, so the rules can come after the launches.
	for _, st := range sites {
		if cidrs := peerCIDRs(hosts, st); len(cidrs) > 0 {
			if err := st.aws.AllowFrom(ctx, st.securityGroup, cidrs); err != nil {
				return infra(runTag, fmt.Errorf("%s: %w", st.region, err)), nil
			}
		}
	}

	until := deadlineAt.Add(uploadSlack)
	client := insts["client"]
	if err := r.wait(ctx, client, keys.NodeOutput("client", "agent.json"), until); err != nil {
		return r.failed(ctx, client, err), nil
	}
	dir, err := r.collect(ctx, func(name string) string { return keys.NodeOutput("client", name) })
	if err != nil {
		return infra(runTag, fmt.Errorf("get the outputs of the client host: %w", err)), nil
	}
	// The other hosts end soon after the client. They get a short time to put their outputs.
	grace := time.Now().Add(nodeGrace)
	if grace.Before(until) {
		until = grace
	}
	for _, role := range []string{"server", "relay", "relay2"} {
		inst, ok := insts[role]
		if !ok {
			continue
		}
		keyOf := func(name string) string { return keys.NodeOutput(role, name) }
		var node *dagger.Directory
		if err := r.wait(ctx, inst, keyOf("agent.json"), until); err != nil {
			node = r.failed(ctx, inst, fmt.Errorf("%s host: %w", role, err))
		} else if node, err = r.collect(ctx, keyOf); err != nil {
			node = infra(runTag, fmt.Errorf("get the outputs of the %s host: %w", role, err))
		}
		dir = dir.WithDirectory("nodes/"+role, node)
	}
	return dir, nil
}

// site is the part of a multi-node run in one region.
type site struct {
	aws           *dagger.Aws
	region, image string
	// subnet is the subnet of the first host. The hosts of one placement group
	// must be in one subnet.
	subnet string
	// securityGroup is the group of the run, or empty in a run in one region.
	securityGroup string
}

// host is one launched host. public is empty in a run in one region.
type host struct {
	site            *site
	private, public string
}

// nodeAddrs returns the address of each host for a new host in the site st: the
// private IP of a host in the same region, else its public IP.
func nodeAddrs(hosts map[string]host, st *site) map[string]string {
	addrs := map[string]string{}
	for role, h := range hosts {
		if h.site == st {
			addrs[role] = h.private
		} else {
			addrs[role] = h.public
		}
	}
	return addrs
}

// peerCIDRs returns the public addresses of the hosts that are not in the site st.
func peerCIDRs(hosts map[string]host, st *site) []string {
	var cidrs []string
	for _, h := range hosts {
		if h.site != st && h.public != "" {
			cidrs = append(cidrs, h.public+"/32")
		}
	}
	slices.Sort(cidrs)
	return cidrs
}

// Ec2Cleanup terminates the live instances of a run and deletes its placement
// groups, its security groups and its inputs in S3. A cancelled job runs it,
// because a cancel stops Ec2 and Ec2Nodes before their own cleanup. With nothing
// left, it does nothing. The result lists what the run still has in each region.
func (m *Perf) Ec2Cleanup(
	ctx context.Context,
	// The run tag of the Ec2 call.
	runTag string,
	bucket string,
	// +default="us-west-2"
	region string,
	accessKeyId *dagger.Secret,
	secretAccessKey *dagger.Secret,
	// +optional
	sessionToken *dagger.Secret,
	// Replaces the AWS endpoints, for example with a local AWS fake.
	// +optional
	endpoint string,
	// The second region of a run with two relays.
	// +optional
	peerRegion string,
) (string, error) {
	keys, err := perfspec.NewKeys(runTag)
	if err != nil {
		return "", err
	}
	regions := []string{region}
	if peerRegion != "" && peerRegion != region {
		regions = append(regions, peerRegion)
	}
	tag, group := perfspec.RunTag(runTag), perfspec.GroupName(runTag)
	var errs []error
	var done, left []string
	for i, rg := range regions {
		a := awsIn(rg, accessKeyId, secretAccessKey, sessionToken, endpoint)
		// Do the next deletes also when one fails.
		ids, err := a.Reap(ctx, dagger.AwsReapOpts{Tag: tag, All: true})
		errs = append(errs, err)
		if i == 0 {
			n, err := a.Bucket(bucket).Delete(ctx, keys.Inputs())
			errs = append(errs, err)
			done = append(done, fmt.Sprintf("deleted %d input objects", n))
		}
		// The groups are free when their instances have terminated.
		errs = append(errs, a.DeletePlacementGroup(ctx, group, dagger.AwsDeletePlacementGroupOpts{Wait: groupDeleteWait}))
		sgs, err := a.DeleteSecurityGroups(ctx, tag, dagger.AwsDeleteSecurityGroupsOpts{Wait: groupDeleteWait})
		errs = append(errs, err)
		done = append(done, fmt.Sprintf("%s: terminated %d instances %v, deleted the placement group %s and %d security groups %v", rg, len(ids), ids, group, len(sgs), sgs))

		insts, err := a.Instances(ctx, dagger.AwsInstancesOpts{Tag: tag})
		errs = append(errs, err)
		pgs, err := a.PlacementGroups(ctx, dagger.AwsPlacementGroupsOpts{Tag: tag})
		errs = append(errs, err)
		rest, err := a.SecurityGroups(ctx, dagger.AwsSecurityGroupsOpts{Tag: tag})
		errs = append(errs, err)
		left = append(left, fmt.Sprintf("%s: %d instances %v, %d placement groups %v, %d security groups %v", rg, len(insts), insts, len(pgs), pgs, len(rest), rest))
	}
	if err := errors.Join(errs...); err != nil {
		return "", err
	}
	return fmt.Sprintf("Run %s: %s.\nLeft with the tag %s: %s.", runTag, strings.Join(done, "; "), tag, strings.Join(left, "; ")), nil
}

// ec2Run is the state of one Ec2 or Ec2Nodes call.
type ec2Run struct {
	aws     *dagger.Aws
	bucket  *dagger.AwsBucket
	runTag  string
	keys    perfspec.Keys
	expires string
}

func newEC2Run(region string, accessKeyId, secretAccessKey, sessionToken *dagger.Secret, endpoint, bucket, runTag string, keys perfspec.Keys, d time.Duration) *ec2Run {
	a := awsIn(region, accessKeyId, secretAccessKey, sessionToken, endpoint)
	return &ec2Run{aws: a, bucket: a.Bucket(bucket), runTag: runTag, keys: keys, expires: (d + 10*time.Minute).String()}
}

// awsIn returns the AWS session of a region.
func awsIn(region string, accessKeyId, secretAccessKey, sessionToken *dagger.Secret, endpoint string) *dagger.Aws {
	return dag.Aws(dagger.AwsOpts{
		Region:          region,
		AccessKeyID:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Endpoint:        endpoint,
	})
}

// launchOpts are the EC2 settings of one host.
type launchOpts struct {
	image, instanceType, subnetTag string
	// subnet and group are set for the hosts of a multi-node run.
	subnet, group string
	// securityGroup is set for the hosts of a run in two regions.
	securityGroup string
}

// reap terminates the expired bench instances of the region of a, and deletes
// the expired placement groups and security groups with no instances.
func reap(ctx context.Context, a *dagger.Aws) {
	ids, err := a.Reap(ctx)
	if err != nil {
		slog.Warn("Failed to terminate expired bench instances", "error", err)
	} else if len(ids) > 0 {
		slog.Info("Terminated expired bench instances", "instances", ids)
	}
	groups, err := a.ReapPlacementGroups(ctx)
	if err != nil {
		slog.Warn("Failed to delete empty bench placement groups", "error", err)
	} else if len(groups) > 0 {
		slog.Info("Deleted empty bench placement groups", "groups", groups)
	}
	sgs, err := a.ReapSecurityGroups(ctx)
	if err != nil {
		slog.Warn("Failed to delete expired bench security groups", "error", err)
	} else if len(sgs) > 0 {
		slog.Info("Deleted expired bench security groups", "groups", sgs)
	}
}

func (r *ec2Run) terminate(ctx context.Context, inst *dagger.AwsInstance, id string) {
	if err := inst.Terminate(ctx); err != nil {
		slog.Warn("Failed to terminate the instance", "instance", id, "error", err)
	}
}

func deleteGroup(ctx context.Context, a *dagger.Aws, group string) {
	if err := a.DeletePlacementGroup(ctx, group, dagger.AwsDeletePlacementGroupOpts{Wait: groupDeleteWait}); err != nil {
		slog.Warn("Failed to delete the placement group", "group", group, "error", err)
		return
	}
	slog.Info("Deleted the placement group", "group", group)
}

// deleteSecurityGroups deletes the security groups of the run in the region of st.
func deleteSecurityGroups(ctx context.Context, st *site, runTag string) {
	ids, err := st.aws.DeleteSecurityGroups(ctx, perfspec.RunTag(runTag), dagger.AwsDeleteSecurityGroupsOpts{Wait: groupDeleteWait})
	if err != nil {
		slog.Warn("Failed to delete the security groups of the run", "region", st.region, "error", err)
		return
	}
	slog.Info("Deleted the security groups of the run", "region", st.region, "groups", ids)
}

// failed returns the infra error of a host, with its console output when it is readable.
func (r *ec2Run) failed(ctx context.Context, inst *dagger.AwsInstance, err error) *dagger.Directory {
	dir := infra(r.runTag, err)
	if console, cerr := inst.Console(context.WithoutCancel(ctx)); cerr == nil {
		dir = dir.WithNewFile("console.txt", console)
	}
	return dir
}

// collect downloads the outputs of a host with the keys of keyOf.
func (r *ec2Run) collect(ctx context.Context, keyOf func(string) string) (*dagger.Directory, error) {
	var results, agentLog *dagger.File
	if ok, err := r.bucket.Exists(ctx, keyOf("results.tgz")); err == nil && ok {
		results = r.bucket.Download(keyOf("results.tgz"))
	}
	if ok, err := r.bucket.Exists(ctx, keyOf("agent.log")); err == nil && ok {
		agentLog = r.bucket.Download(keyOf("agent.log"))
	}
	return collect(ctx, r.bucket.Download(keyOf("agent.json")), agentLog, results)
}

func (r *ec2Run) cleanup(ctx context.Context) {
	n, err := r.bucket.Delete(ctx, r.keys.Inputs())
	if err != nil {
		slog.Warn("Failed to delete the run inputs", "prefix", r.keys.Inputs(), "error", err)
		return
	}
	slog.Info("Deleted the run inputs", "objects", n)
}

func (r *ec2Run) presign(ctx context.Context, key, method string) (string, error) {
	return r.bucket.Presign(key, dagger.AwsBucketPresignOpts{Method: method, Expires: r.expires}).Plaintext(ctx)
}

// inputs puts the binaries and files in S3, fills the spec with their URLs,
// and returns the URL of perfagent.
func (r *ec2Run) inputs(ctx context.Context, spec *perfspec.Spec, bins, files *dagger.Directory) (string, error) {
	put := func(dir *dagger.Directory, key func(string) string, skipAgent bool) ([]perfspec.File, string, error) {
		names, err := fileNames(ctx, dir)
		if err != nil {
			return nil, "", err
		}
		var out []perfspec.File
		var agentURL string
		for _, n := range names {
			sum, err := r.bucket.Upload(ctx, key(n), dir.File(n))
			if err != nil {
				return nil, "", err
			}
			u, err := r.presign(ctx, key(n), "GET")
			if err != nil {
				return nil, "", err
			}
			if skipAgent && n == perfspec.Agent {
				agentURL = u
				continue
			}
			out = append(out, perfspec.File{Name: n, URL: u, SHA256: sum})
		}
		return out, agentURL, nil
	}
	var agentURL string
	var err error
	if spec.Bins, agentURL, err = put(bins, r.keys.Bin, true); err != nil {
		return "", err
	}
	if agentURL == "" {
		return "", fmt.Errorf("the bins have no %s", perfspec.Agent)
	}
	if files != nil {
		if spec.Files, _, err = put(files, r.keys.File, false); err != nil {
			return "", err
		}
	}
	return agentURL, nil
}

// uploads fills the spec with the upload URLs of the outputs with the keys of keyOf.
func (r *ec2Run) uploads(ctx context.Context, spec *perfspec.Spec, keyOf func(string) string) error {
	for _, o := range []struct {
		name string
		dst  *string
	}{
		{"results.tgz", &spec.Upload.Results},
		{"agent.log", &spec.Upload.Log},
		{"agent.json", &spec.Upload.Report},
	} {
		var err error
		if *o.dst, err = r.presign(ctx, keyOf(o.name), "PUT"); err != nil {
			return err
		}
	}
	return nil
}

// launch puts the spec in S3 at specKey and launches the instance in the region of a.
func (r *ec2Run) launch(ctx context.Context, a *dagger.Aws, spec perfspec.Spec, specKey, agentURL string, o launchOpts, at time.Time) (string, error) {
	js, err := spec.JSON()
	if err != nil {
		return "", err
	}
	if err := r.bucket.PutSecret(ctx, specKey, dag.SetSecret("perf-spec-"+path.Base(specKey)+"-"+spec.RunID, js)); err != nil {
		return "", err
	}
	specURL, err := r.presign(ctx, specKey, "GET")
	if err != nil {
		return "", err
	}
	ud, err := perfspec.CloudInit(agentURL, specURL, poweroff)
	if err != nil {
		return "", err
	}
	return a.Launch(ctx, o.image, o.instanceType, dag.SetSecret("perf-user-data-"+path.Base(specKey)+"-"+spec.RunID, ud),
		perfspec.Tags(spec.RunID, at.Add(poweroff)),
		dagger.AwsLaunchOpts{SubnetTag: o.subnetTag, Subnet: o.subnet, PlacementGroup: o.group, SecurityGroup: o.securityGroup})
}

// wait waits for the key until the time. It fails early when the instance stops.
func (r *ec2Run) wait(ctx context.Context, inst *dagger.AwsInstance, key string, until time.Time) error {
	done := func() bool {
		ok, err := r.bucket.Exists(ctx, key)
		if err != nil {
			slog.Warn("Failed to look for agent.json", "error", err)
		}
		return ok
	}
	for {
		if done() {
			return nil
		}
		state, err := inst.State(ctx)
		if err != nil {
			slog.Warn("Failed to read the instance state", "error", err)
		}
		switch state {
		case "shutting-down", "terminated", "stopping", "stopped":
			// perfagent puts agent.json before it powers off the host.
			if done() {
				return nil
			}
			return fmt.Errorf("the instance is %s and perfagent put no agent.json", state)
		}
		if time.Now().After(until) {
			return fmt.Errorf("perfagent put no agent.json by %s, %s after the deadline", until.Format(time.RFC3339), uploadSlack)
		}
		slog.Info("Waiting for perfagent", "state", state)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollEvery):
		}
	}
}

func parse(plan, deadline string) (perfspec.Spec, time.Duration, error) {
	spec, err := perfspec.ParsePlan(plan)
	if err != nil {
		return spec, 0, err
	}
	d, err := time.ParseDuration(deadline)
	if err != nil || d <= 0 {
		return spec, 0, fmt.Errorf("bad deadline %q", deadline)
	}
	return spec, d, nil
}

// infra returns an output directory with only an agent.json that has the error.
func infra(runID string, err error) *dagger.Directory {
	slog.Error("The perf run has an infra error", "run", runID, "error", err)
	return dag.Directory().WithNewFile("agent.json", perfspec.InfraReport(runID, err))
}

var unpacks atomic.Int32

// collect unpacks the results and adds agent.json and agent.log. results and
// agentLog can be nil.
func collect(ctx context.Context, agentJSON, agentLog, results *dagger.File) (*dagger.Directory, error) {
	dir := dag.Directory()
	if results != nil {
		tmp, err := os.MkdirTemp("", "results")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		path, err := results.Export(ctx, filepath.Join(tmp, "results.tgz"))
		if err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		// Workdir reads from the module workdir, so the files go there.
		name := fmt.Sprintf("unpack-%d", unpacks.Add(1))
		if err := perfspec.Untar(f, name); err != nil {
			return nil, fmt.Errorf("unpack the results: %w", err)
		}
		dir = dag.CurrentModule().Workdir(name)
	}
	dir = dir.WithFile("agent.json", agentJSON)
	if agentLog != nil {
		dir = dir.WithFile("agent.log", agentLog)
	}
	return dir.Sync(ctx)
}

// fileNames returns the names of the regular files at the top of dir.
func fileNames(ctx context.Context, dir *dagger.Directory) ([]string, error) {
	ents, err := dir.Entries(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !strings.HasSuffix(e, "/") {
			names = append(names, e)
		}
	}
	return names, nil
}

func has(ctx context.Context, dir *dagger.Directory, name string) bool {
	names, err := fileNames(ctx, dir)
	if err != nil {
		return false
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// hashAll returns the files at the top of dir with their SHA-256 and no URL.
func hashAll(ctx context.Context, dir *dagger.Directory, skipAgent bool) ([]perfspec.File, error) {
	names, err := fileNames(ctx, dir)
	if err != nil {
		return nil, err
	}
	var out []perfspec.File
	for _, n := range names {
		if skipAgent && n == perfspec.Agent {
			continue
		}
		sum, err := hashFile(ctx, dir.File(n))
		if err != nil {
			return nil, err
		}
		out = append(out, perfspec.File{Name: n, SHA256: sum})
	}
	return out, nil
}

func hashFile(ctx context.Context, f *dagger.File) (string, error) {
	tmp, err := os.MkdirTemp("", "hash")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	path, err := f.Export(ctx, filepath.Join(tmp, "f"))
	if err != nil {
		return "", err
	}
	r, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
