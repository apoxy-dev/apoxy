// Module aws has the EC2 and S3 functions of the perf bench: buckets,
// presigned URLs, and instances that the bench launches and terminates. The
// functions that read a state or make a change have no cache, so that a poll
// or a second call in a session calls AWS again.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dagger/aws/awsx"
	"dagger/aws/internal/dagger"
)

// Aws is an AWS session in one region.
type Aws struct {
	Region string
	// +private
	AccessKeyId *dagger.Secret
	// +private
	SecretAccessKey *dagger.Secret
	// +private
	SessionToken *dagger.Secret
	// +private
	Endpoint string
}

// New uses the static credentials when they are set, else the default AWS
// credential chain of the module runtime.
func New(
	// +default="us-west-2"
	region string,
	// +optional
	accessKeyId *dagger.Secret,
	// +optional
	secretAccessKey *dagger.Secret,
	// +optional
	sessionToken *dagger.Secret,
	// Replaces the AWS endpoints, for example with a local AWS fake.
	// +optional
	endpoint string,
) *Aws {
	return &Aws{
		Region:          region,
		AccessKeyId:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Endpoint:        endpoint,
	}
}

func (m *Aws) client(ctx context.Context) (*awsx.Client, error) {
	o := awsx.Options{Region: m.Region, Endpoint: m.Endpoint}
	for _, s := range []struct {
		secret *dagger.Secret
		dst    *string
	}{
		{m.AccessKeyId, &o.AccessKeyID},
		{m.SecretAccessKey, &o.SecretAccessKey},
		{m.SessionToken, &o.SessionToken},
	} {
		if s.secret == nil {
			continue
		}
		v, err := s.secret.Plaintext(ctx)
		if err != nil {
			return nil, err
		}
		*s.dst = v
	}
	return awsx.New(ctx, o)
}

// Bucket returns an S3 bucket. It makes no AWS call.
func (m *Aws) Bucket(name string) *Bucket {
	return &Bucket{Aws: m, Name: name}
}

// EnsureBucket makes the bucket when it does not exist, and sets its settings:
// no public access, TLS only, and the objects under runs/ expire after 7 days.
func (m *Aws) EnsureBucket(ctx context.Context, name string) (*Bucket, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := c.EnsureBucket(ctx, name); err != nil {
		return nil, err
	}
	return m.Bucket(name), nil
}

// Bucket is an S3 bucket.
type Bucket struct {
	// +private
	Aws  *Aws
	Name string
}

// Upload puts the file at the key and returns the SHA-256 of its content in hex.
// +cache="never"
func (b *Bucket) Upload(ctx context.Context, key string, file *dagger.File) (string, error) {
	c, err := b.Aws.client(ctx)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "upload")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path, err := file.Export(ctx, filepath.Join(dir, "f"))
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if err := c.Put(ctx, b.Name, key, f, size); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PutSecret puts the plaintext of a secret at the key, for example a spec
// with presigned URLs. Its content does not show in traces.
// +cache="never"
func (b *Bucket) PutSecret(ctx context.Context, key string, contents *dagger.Secret) error {
	c, err := b.Aws.client(ctx)
	if err != nil {
		return err
	}
	v, err := contents.Plaintext(ctx)
	if err != nil {
		return err
	}
	return c.Put(ctx, b.Name, key, strings.NewReader(v), int64(len(v)))
}

// Presign returns a URL that lets its holder GET or PUT the key until it expires.
func (b *Bucket) Presign(
	ctx context.Context,
	key string,
	// GET or PUT.
	// +default="GET"
	method string,
	// For example 50m. A URL made with session credentials ends with the session.
	// +default="50m"
	expires string,
) (*dagger.Secret, error) {
	d, err := time.ParseDuration(expires)
	if err != nil {
		return nil, fmt.Errorf("bad expires %q: %w", expires, err)
	}
	c, err := b.Aws.client(ctx)
	if err != nil {
		return nil, err
	}
	u, err := c.Presign(ctx, b.Name, key, strings.ToUpper(method), d)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(u))
	return dag.SetSecret("presign-"+hex.EncodeToString(sum[:8]), u), nil
}

// Exists tells if the key exists.
// +cache="never"
func (b *Bucket) Exists(ctx context.Context, key string) (bool, error) {
	c, err := b.Aws.client(ctx)
	if err != nil {
		return false, err
	}
	return c.Exists(ctx, b.Name, key)
}

// Download returns the object at the key as a file.
func (b *Bucket) Download(ctx context.Context, key string) (*dagger.File, error) {
	c, err := b.Aws.client(ctx)
	if err != nil {
		return nil, err
	}
	r, err := c.Get(ctx, b.Name, key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// WorkdirFile reads from the module workdir, so the file goes there.
	if err := os.MkdirAll("download", 0o755); err != nil {
		return nil, err
	}
	name := filepath.Join("download", hexName(key))
	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return nil, fmt.Errorf("download s3://%s/%s: %w", b.Name, key, err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return dag.CurrentModule().WorkdirFile(name), nil
}

// Delete deletes all keys with the prefix and returns their count.
// +cache="never"
func (b *Bucket) Delete(ctx context.Context, prefix string) (int, error) {
	c, err := b.Aws.client(ctx)
	if err != nil {
		return 0, err
	}
	return c.DeletePrefix(ctx, b.Name, prefix)
}

// Launch starts one instance that terminates when it powers off, with IMDSv2
// required, and returns its ID. It tries the next subnet when a subnet has no
// capacity. With no subnet with subnetTag, it uses the default VPC, with the
// group with subnetTag in that VPC, else its default group.
// +cache="never"
func (m *Aws) Launch(
	ctx context.Context,
	image string,
	instanceType string,
	// cloud-init user data.
	userData *dagger.Secret,
	// KEY=VALUE tags of the instance and its volumes.
	tags []string,
	// KEY=VALUE tag of the subnets and the security group.
	// +default="apoxy-perf=true"
	subnetTag string,
	// The only subnet to use, for the hosts of one placement group.
	// +optional
	subnet string,
	// The cluster placement group of the instance.
	// +optional
	placementGroup string,
	// The one security group of the instance, in the place of the group with subnetTag.
	// +optional
	securityGroup string,
) (string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return "", err
	}
	ud, err := userData.Plaintext(ctx)
	if err != nil {
		return "", err
	}
	t, err := parseTags(tags)
	if err != nil {
		return "", err
	}
	in := awsx.LaunchInput{
		Image: image, InstanceType: instanceType, UserData: ud, Tags: t,
		SubnetTag: subnetTag, Subnet: subnet, PlacementGroup: placementGroup, SecurityGroup: securityGroup,
	}
	return c.Launch(ctx, in)
}

// Instance returns an EC2 instance. It makes no AWS call.
func (m *Aws) Instance(instanceId string) *Instance {
	return &Instance{Aws: m, InstanceId: instanceId}
}

// CreatePlacementGroup makes a cluster placement group with the tags. A group
// with the name that exists is not an error.
// +cache="never"
func (m *Aws) CreatePlacementGroup(
	ctx context.Context,
	name string,
	// KEY=VALUE tags of the group.
	tags []string,
) error {
	c, err := m.client(ctx)
	if err != nil {
		return err
	}
	t, err := parseTags(tags)
	if err != nil {
		return err
	}
	return c.CreatePlacementGroup(ctx, name, t)
}

// DeletePlacementGroup deletes the group. A group that EC2 does not know is
// not an error. While the group has instances, it tries again until wait ends.
// +cache="never"
func (m *Aws) DeletePlacementGroup(
	ctx context.Context,
	name string,
	// Time to wait for the instances of the group to terminate, for example 3m.
	// +default="0s"
	wait string,
) error {
	d, err := time.ParseDuration(wait)
	if err != nil {
		return fmt.Errorf("bad wait %q: %w", wait, err)
	}
	c, err := m.client(ctx)
	if err != nil {
		return err
	}
	return c.DeletePlacementGroup(ctx, name, d)
}

// PlacementGroups returns the placement groups with the tag, each as its name
// and its state. A check after a run uses it with the tag of the run.
// +cache="never"
func (m *Aws) PlacementGroups(
	ctx context.Context,
	// +default="apoxy-perf=true"
	tag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.PlacementGroups(ctx, tag)
}

// ReapPlacementGroups deletes the empty placement groups with the tag whose
// expiry tag (RFC 3339) is in the past, and returns their names.
// +cache="never"
func (m *Aws) ReapPlacementGroups(
	ctx context.Context,
	// +default="apoxy-perf=true"
	tag string,
	// +default="apoxy-perf-expires"
	expiryTag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.ReapPlacementGroups(ctx, tag, expiryTag, time.Now())
}

// CreateSecurityGroup makes a security group with the tags in the VPC that Launch
// uses with subnetTag, and returns its ID. The members of the group can send to
// each other. A group with the name that the VPC has already is not an error.
// +cache="never"
func (m *Aws) CreateSecurityGroup(
	ctx context.Context,
	name string,
	// KEY=VALUE tags of the group.
	tags []string,
	// KEY=VALUE tag of the subnets, as for Launch.
	// +default="apoxy-perf=true"
	subnetTag string,
) (string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return "", err
	}
	t, err := parseTags(tags)
	if err != nil {
		return "", err
	}
	return c.CreateSecurityGroup(ctx, name, subnetTag, t)
}

// AllowFrom lets the addresses of cidrs send all traffic to the members of the
// security group, for example the hosts of a run in another region.
// +cache="never"
func (m *Aws) AllowFrom(ctx context.Context, securityGroup string, cidrs []string) error {
	c, err := m.client(ctx)
	if err != nil {
		return err
	}
	return c.AllowFrom(ctx, securityGroup, cidrs)
}

// DeleteSecurityGroups deletes the security groups with the tag and returns
// their IDs. While an instance uses a group, it tries again until wait ends.
// +cache="never"
func (m *Aws) DeleteSecurityGroups(
	ctx context.Context,
	// KEY=VALUE tag of the groups, for example the tag of one run.
	tag string,
	// Time to wait for the instances of a group to terminate, for example 3m.
	// +default="0s"
	wait string,
) ([]string, error) {
	d, err := time.ParseDuration(wait)
	if err != nil {
		return nil, fmt.Errorf("bad wait %q: %w", wait, err)
	}
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.DeleteSecurityGroups(ctx, tag, d)
}

// SecurityGroups returns the security groups with the tag, each as its ID and
// its name. A check after a run uses it with the tag of the run.
// +cache="never"
func (m *Aws) SecurityGroups(
	ctx context.Context,
	// +default="apoxy-perf-group=true"
	tag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.SecurityGroups(ctx, tag)
}

// ReapSecurityGroups deletes the security groups with the tag that no instance
// uses and whose expiry tag (RFC 3339) is in the past, and returns their IDs.
// +cache="never"
func (m *Aws) ReapSecurityGroups(
	ctx context.Context,
	// +default="apoxy-perf-group=true"
	tag string,
	// +default="apoxy-perf-expires"
	expiryTag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.ReapSecurityGroups(ctx, tag, expiryTag, time.Now())
}

// Instances returns the instances with the tag that did not terminate yet, each
// as its ID and its state. A check after a run uses it with the tag of the run.
// +cache="never"
func (m *Aws) Instances(
	ctx context.Context,
	// +default="apoxy-perf=true"
	tag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.Instances(ctx, tag)
}

// NetworkInterfaces returns the network interfaces with the tag, each as its ID
// and its status. A check after a run uses it with the tag of the run.
// +cache="never"
func (m *Aws) NetworkInterfaces(
	ctx context.Context,
	// +default="apoxy-perf=true"
	tag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.NetworkInterfaces(ctx, tag)
}

// DeleteNetworkInterfaces deletes the network interfaces with the tag and
// returns their IDs. While an interface is attached, it tries again until wait
// ends. An interface that EC2 deleted with its instance is not an error.
// +cache="never"
func (m *Aws) DeleteNetworkInterfaces(
	ctx context.Context,
	// KEY=VALUE tag of the interfaces, for example the tag of one run.
	tag string,
	// Time to wait for the instances of the interfaces to terminate, for example 3m.
	// +default="0s"
	wait string,
) ([]string, error) {
	d, err := time.ParseDuration(wait)
	if err != nil {
		return nil, fmt.Errorf("bad wait %q: %w", wait, err)
	}
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.DeleteNetworkInterfaces(ctx, tag, d)
}

// ReapNetworkInterfaces deletes the available network interfaces with the tag
// whose expiry tag (RFC 3339) is in the past, and returns their IDs.
// +cache="never"
func (m *Aws) ReapNetworkInterfaces(
	ctx context.Context,
	// +default="apoxy-perf=true"
	tag string,
	// +default="apoxy-perf-expires"
	expiryTag string,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.ReapNetworkInterfaces(ctx, tag, expiryTag, time.Now())
}

// parseTags reads KEY=VALUE tags.
func parseTags(tags []string) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range tags {
		k, v, ok := strings.Cut(t, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("bad tag %q: want KEY=VALUE", t)
		}
		out[k] = v
	}
	return out, nil
}

// Reap terminates the live instances with the tag whose expiry tag (RFC 3339)
// is in the past, or all of them with all set, and returns their IDs.
// +cache="never"
func (m *Aws) Reap(
	ctx context.Context,
	// +default="apoxy-perf=true"
	tag string,
	// +default="apoxy-perf-expires"
	expiryTag string,
	// Terminate the instances that did not expire too.
	// +optional
	all bool,
) ([]string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.Reap(ctx, tag, expiryTag, time.Now(), all)
}

// Instance is an EC2 instance.
type Instance struct {
	// +private
	Aws        *Aws
	InstanceId string
}

// State returns the instance state, for example running, or not-found.
// +cache="never"
func (i *Instance) State(ctx context.Context) (string, error) {
	c, err := i.Aws.client(ctx)
	if err != nil {
		return "", err
	}
	return c.State(ctx, i.InstanceId)
}

// InstanceFacts are the facts of a launched instance.
type InstanceFacts struct {
	State     string
	PrivateIp string
	SubnetId  string
	Az        string
}

// Facts returns the state, the private IP, the subnet and the AZ of the instance.
// +cache="never"
func (i *Instance) Facts(ctx context.Context) (*InstanceFacts, error) {
	c, err := i.Aws.client(ctx)
	if err != nil {
		return nil, err
	}
	f, err := c.Facts(ctx, i.InstanceId)
	if err != nil {
		return nil, err
	}
	return &InstanceFacts{State: f.State, PrivateIp: f.PrivateIP, SubnetId: f.SubnetID, Az: f.AZ}, nil
}

// PublicIp returns the public IPv4 address of the instance. EC2 gives it a short
// time after the launch, so it reads again until wait ends.
// +cache="never"
func (i *Instance) PublicIp(
	ctx context.Context,
	// Time to wait for the address, for example 2m.
	wait string,
) (string, error) {
	d, err := time.ParseDuration(wait)
	if err != nil {
		return "", fmt.Errorf("bad wait %q: %w", wait, err)
	}
	c, err := i.Aws.client(ctx)
	if err != nil {
		return "", err
	}
	return c.PublicIP(ctx, i.InstanceId, d)
}

// AttachNewInterface makes a network interface with the tags in the subnet and
// with the security groups of the instance, and attaches it at device index 1.
// EC2 deletes it when the instance terminates. It waits for the instance to run.
// It returns the interface ID.
// +cache="never"
func (i *Instance) AttachNewInterface(
	ctx context.Context,
	// KEY=VALUE tags of the interface.
	tags []string,
	// Time to wait for the instance to run, for example 3m.
	// +default="3m"
	wait string,
) (string, error) {
	d, err := time.ParseDuration(wait)
	if err != nil {
		return "", fmt.Errorf("bad wait %q: %w", wait, err)
	}
	t, err := parseTags(tags)
	if err != nil {
		return "", err
	}
	c, err := i.Aws.client(ctx)
	if err != nil {
		return "", err
	}
	return c.AttachNewInterface(ctx, i.InstanceId, t, d)
}

// Console returns the serial console output.
// +cache="never"
func (i *Instance) Console(ctx context.Context) (string, error) {
	c, err := i.Aws.client(ctx)
	if err != nil {
		return "", err
	}
	return c.Console(ctx, i.InstanceId)
}

// Terminate terminates the instance.
// +cache="never"
func (i *Instance) Terminate(ctx context.Context) error {
	c, err := i.Aws.client(ctx)
	if err != nil {
		return err
	}
	return c.Terminate(ctx, i.InstanceId)
}

func hexName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:12])
}
