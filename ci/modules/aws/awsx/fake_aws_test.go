package awsx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
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

		n, err := c.DeletePrefix(ctx, bucket, RunsPrefix+"1-1-vpc/")
		if err != nil || n != 2 {
			t.Fatalf("DeletePrefix = %d, %v, want 2", n, err)
		}
	})

	t.Run("ec2", func(t *testing.T) {
		in := LaunchInput{
			Image: "ami-12c6146b", InstanceType: "c7a.8xlarge", UserData: "#cloud-config\n",
			Tags: map[string]string{
				"apoxy-perf":         "true",
				"apoxy-perf-run":     "1-1-vpc",
				"apoxy-perf-expires": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
			},
			SubnetTag: "apoxy-perf=true",
		}
		// No subnet has the tag, so Launch uses the default VPC.
		id, err := c.Launch(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if st, err := c.State(ctx, id); err != nil || st != "running" && st != "pending" {
			t.Fatalf("State = %q, %v", st, err)
		}
		reaped, err := c.Reap(ctx, "apoxy-perf=true", "apoxy-perf-expires", time.Now())
		if err != nil || len(reaped) != 1 || reaped[0] != id {
			t.Fatalf("Reap = %v, %v, want [%s]", reaped, err, id)
		}
		if st, err := c.State(ctx, id); err != nil || st != "terminated" && st != "shutting-down" {
			t.Fatalf("State after Reap = %q, %v", st, err)
		}
		if err := c.Terminate(ctx, id); err != nil {
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
