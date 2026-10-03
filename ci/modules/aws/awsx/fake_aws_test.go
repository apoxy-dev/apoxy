package awsx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestFakeAWS runs the S3 and EC2 calls against a local AWS fake (moto server).
// It runs only when AWS_ENDPOINT_URL is set, for example by the PerfAwsTest
// function of the CI module.
func TestFakeAWS(t *testing.T) {
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Skip("AWS_ENDPOINT_URL is not set")
	}
	ctx := context.Background()
	c, err := New(ctx, Options{Region: "us-west-2", AccessKeyID: "test", SecretAccessKey: "test"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("s3", func(t *testing.T) {
		const bucket = "apoxy-perf-test"
		for i, want := range []bool{true, false} {
			made, err := c.EnsureBucket(ctx, bucket)
			if err != nil || made != want {
				t.Fatalf("EnsureBucket %d = %v, %v, want %v", i, made, err, want)
			}
		}
		pol, err := c.s3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
		if err != nil || !strings.Contains(aws.ToString(pol.Policy), "aws:SecureTransport") {
			t.Fatalf("bucket policy = %v, %v", pol, err)
		}
		lc, err := c.s3.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(bucket)})
		if err != nil || len(lc.Rules) != 1 || aws.ToInt32(lc.Rules[0].Expiration.Days) != 7 {
			t.Fatalf("bucket lifecycle = %v, %v", lc, err)
		}
		key := RunsPrefix + "1-1-vpc/spec.json"
		// The fake has no TLS, so the policy refuses all requests. Remove it for the next checks.
		if _, err := c.Exists(ctx, bucket, key); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("Exists with no TLS = %v, want a 403 error", err)
		}
		if _, err := c.s3.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: aws.String(bucket)}); err != nil {
			t.Fatal(err)
		}
		if ok, err := c.Exists(ctx, bucket, key); err != nil || ok {
			t.Fatalf("Exists before Put = %v, %v", ok, err)
		}
		if err := c.Put(ctx, bucket, key, strings.NewReader("spec"), 4); err != nil {
			t.Fatal(err)
		}
		if ok, err := c.Exists(ctx, bucket, key); err != nil || !ok {
			t.Fatalf("Exists after Put = %v, %v", ok, err)
		}

		get, err := c.Presign(ctx, bucket, key, http.MethodGet, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if body := httpDo(t, http.MethodGet, get, nil); body != "spec" {
			t.Fatalf("presigned GET = %q", body)
		}
		putKey := RunsPrefix + "1-1-vpc/agent.json"
		put, err := c.Presign(ctx, bucket, putKey, http.MethodPut, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		httpDo(t, http.MethodPut, put, []byte(`{"run_id": "1-1-vpc"}`))
		r, err := c.Get(ctx, bucket, putKey)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(r)
		r.Close()
		if string(got) != `{"run_id": "1-1-vpc"}` {
			t.Fatalf("Get after presigned PUT = %q", got)
		}

		for _, want := range []int{2, 0} {
			n, err := c.DeletePrefix(ctx, bucket, RunsPrefix+"1-1-vpc/")
			if err != nil || n != want {
				t.Fatalf("DeletePrefix = %d, %v, want %d", n, err, want)
			}
		}
	})

	t.Run("ec2", func(t *testing.T) {
		launch := func(run string, expires time.Time) string {
			t.Helper()
			id, err := c.Launch(ctx, LaunchInput{
				Image: "ami-12c6146b", InstanceType: "c7a.8xlarge", UserData: "#cloud-config\n",
				Tags: map[string]string{
					"apoxy-perf":         "true",
					"apoxy-perf-run":     run,
					"apoxy-perf-expires": expires.UTC().Format(time.RFC3339),
				},
				SubnetTag: "apoxy-perf=true",
			})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		state := func(id string, want ...string) {
			t.Helper()
			st, err := c.State(ctx, id)
			if err != nil || !slices.Contains(want, st) {
				t.Fatalf("State of %s = %q, %v, want one of %v", id, st, err, want)
			}
		}
		reap := func(tag string, all bool, want ...string) {
			t.Helper()
			got, err := c.Reap(ctx, tag, "apoxy-perf-expires", time.Now(), all)
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("Reap(%s, all=%v) = %v, %v, want %v", tag, all, got, err, want)
			}
		}
		// No subnet has the tag, so Launch uses the default VPC.
		expired := launch("1-1-vpc", time.Now().Add(-time.Minute))
		live := launch("2-1-vpc", time.Now().Add(time.Hour))
		state(expired, "running", "pending")
		reap("apoxy-perf=true", false, expired)
		state(expired, "terminated", "shutting-down")
		state(live, "running", "pending")

		// The cleanup of a cancelled run terminates its live instance, then finds nothing.
		reap("apoxy-perf-run=2-1-vpc", true, live)
		state(live, "terminated", "shutting-down")
		reap("apoxy-perf-run=2-1-vpc", true)
		if err := c.Terminate(ctx, expired); err != nil {
			t.Fatal(err)
		}
	})
}

func httpDo(t *testing.T, method, url string, body []byte) string {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: HTTP %d: %s", method, resp.StatusCode, b)
	}
	return string(b)
}
