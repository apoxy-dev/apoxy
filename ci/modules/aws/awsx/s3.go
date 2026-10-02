package awsx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// RunsPrefix is the key prefix of the bench runs. Its objects expire.
const RunsPrefix = "runs/"

// Put writes body to the key. size is the body length.
func (c *Client) Put(ctx context.Context, bucket, key string, body io.Reader, size int64) error {
	_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return fmt.Errorf("put s3://%s/%s: %w", bucket, key, err)
	}
	return nil
}

// Get returns the object body. The caller closes it.
func (c *Client) Get(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("get s3://%s/%s: %w", bucket, key, err)
	}
	return out.Body, nil
}

// Exists tells if the key exists.
func (c *Client) Exists(ctx context.Context, bucket, key string) (bool, error) {
	_, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err == nil {
		return true, nil
	}
	if notFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("head s3://%s/%s: %w", bucket, key, err)
}

// Presign returns a URL that lets its holder GET or PUT one key until it expires.
func (c *Client) Presign(ctx context.Context, bucket, key, method string, expires time.Duration) (string, error) {
	opt := s3.WithPresignExpires(expires)
	var req *v4.PresignedHTTPRequest
	var err error
	switch method {
	case http.MethodGet:
		req, err = c.presign.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}, opt)
	case http.MethodPut:
		req, err = c.presign.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}, opt)
	default:
		return "", fmt.Errorf("presign: method %q is not GET or PUT", method)
	}
	if err != nil {
		return "", fmt.Errorf("presign %s s3://%s/%s: %w", method, bucket, key, err)
	}
	return req.URL, nil
}

// DeletePrefix deletes all keys with the prefix and returns their count.
func (c *Client) DeletePrefix(ctx context.Context, bucket, prefix string) (int, error) {
	if prefix == "" {
		return 0, errors.New("delete: the prefix is empty")
	}
	n := 0
	pages := s3.NewListObjectsV2Paginator(c.s3, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return n, fmt.Errorf("list s3://%s/%s: %w", bucket, prefix, err)
		}
		if len(page.Contents) == 0 {
			continue
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, o := range page.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: o.Key})
		}
		out, err := c.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		})
		if err != nil {
			return n, fmt.Errorf("delete in s3://%s/%s: %w", bucket, prefix, err)
		}
		if len(out.Errors) > 0 {
			e := out.Errors[0]
			return n, fmt.Errorf("delete s3://%s/%s: %s", bucket, aws.ToString(e.Key), aws.ToString(e.Message))
		}
		n += len(ids)
	}
	return n, nil
}

// EnsureBucket makes the bucket when it does not exist, and tells if it made
// it. On each call it sets the settings of the bench bucket: no public access,
// TLS only, and the objects under RunsPrefix expire after 7 days.
func (c *Client) EnsureBucket(ctx context.Context, bucket string) (bool, error) {
	made := false
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	switch {
	case err == nil:
	case !notFound(err):
		return false, fmt.Errorf("head bucket %s: %w", bucket, err)
	default:
		in := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
		// us-east-1 refuses its own name as a location constraint.
		if c.region != "us-east-1" {
			in.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(c.region)}
		}
		if _, err := c.s3.CreateBucket(ctx, in); err != nil {
			return false, fmt.Errorf("create bucket %s: %w", bucket, err)
		}
		made = true
	}
	if _, err := c.s3.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucket),
		PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	}); err != nil {
		return made, fmt.Errorf("block public access of bucket %s: %w", bucket, err)
	}
	if _, err := c.s3.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(tlsOnlyPolicy(bucket)),
	}); err != nil {
		return made, fmt.Errorf("set the policy of bucket %s: %w", bucket, err)
	}
	if _, err := c.s3.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{{
			ID:                             aws.String("expire-runs"),
			Status:                         types.ExpirationStatusEnabled,
			Filter:                         &types.LifecycleRuleFilter{Prefix: aws.String(RunsPrefix)},
			Expiration:                     &types.LifecycleExpiration{Days: aws.Int32(7)},
			AbortIncompleteMultipartUpload: &types.AbortIncompleteMultipartUpload{DaysAfterInitiation: aws.Int32(1)},
		}}},
	}); err != nil {
		return made, fmt.Errorf("set the lifecycle of bucket %s: %w", bucket, err)
	}
	return made, nil
}

// tlsOnlyPolicy refuses all requests to the bucket that do not use TLS.
func tlsOnlyPolicy(bucket string) string {
	arn := "arn:aws:s3:::" + bucket
	return `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*",` +
		`"Action":"s3:*","Resource":["` + arn + `","` + arn + `/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
}

// notFound tells if err is an S3 404.
func notFound(err error) bool {
	var nf *types.NotFound
	var nsk *types.NoSuchKey
	var nsb *types.NoSuchBucket
	if errors.As(err, &nf) || errors.As(err, &nsk) || errors.As(err, &nsb) {
		return true
	}
	var ae smithy.APIError
	return errors.As(err, &ae) && (ae.ErrorCode() == "NotFound" || ae.ErrorCode() == "NoSuchKey" || ae.ErrorCode() == "NoSuchBucket")
}
