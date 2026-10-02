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
) (string, error) {
	c, err := m.client(ctx)
	if err != nil {
		return "", err
	}
	ud, err := userData.Plaintext(ctx)
	if err != nil {
		return "", err
	}
	in := awsx.LaunchInput{Image: image, InstanceType: instanceType, UserData: ud, Tags: map[string]string{}, SubnetTag: subnetTag}
	for _, t := range tags {
		k, v, ok := strings.Cut(t, "=")
		if !ok || k == "" {
			return "", fmt.Errorf("bad tag %q: want KEY=VALUE", t)
		}
		in.Tags[k] = v
	}
	return c.Launch(ctx, in)
}

// Instance returns an EC2 instance. It makes no AWS call.
func (m *Aws) Instance(instanceId string) *Instance {
	return &Instance{Aws: m, InstanceId: instanceId}
}

// Reap terminates the live instances with the tag whose expiry tag (RFC 3339)
// is in the past, and returns their IDs.
// +cache="never"
func (m *Aws) Reap(
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
	return c.Reap(ctx, tag, expiryTag, time.Now())
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
