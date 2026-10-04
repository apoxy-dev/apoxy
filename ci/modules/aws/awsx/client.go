// Package awsx has the EC2 and S3 calls of the perf bench. It has no Dagger
// code, so its tests run with plain go test.
package awsx

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Options configure a Client.
type Options struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// Endpoint replaces the AWS endpoints, for example with a local fake.
	// AWS_ENDPOINT_URL does the same.
	Endpoint string
}

// ec2API is the part of the EC2 client that the bench uses.
type ec2API interface {
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
	GetConsoleOutput(context.Context, *ec2.GetConsoleOutputInput, ...func(*ec2.Options)) (*ec2.GetConsoleOutputOutput, error)
	CreatePlacementGroup(context.Context, *ec2.CreatePlacementGroupInput, ...func(*ec2.Options)) (*ec2.CreatePlacementGroupOutput, error)
	DeletePlacementGroup(context.Context, *ec2.DeletePlacementGroupInput, ...func(*ec2.Options)) (*ec2.DeletePlacementGroupOutput, error)
	DescribePlacementGroups(context.Context, *ec2.DescribePlacementGroupsInput, ...func(*ec2.Options)) (*ec2.DescribePlacementGroupsOutput, error)
}

// Client calls EC2 and S3 in one region.
type Client struct {
	region  string
	ec2     ec2API
	s3      *s3.Client
	presign *s3.PresignClient
}

// New makes a Client. With no access key, it uses the default AWS credential chain.
func New(ctx context.Context, o Options) (*Client, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(o.Region)}
	if o.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(o.AccessKeyID, o.SecretAccessKey, o.SessionToken)))
	}
	if o.Endpoint != "" {
		opts = append(opts, config.WithBaseEndpoint(o.Endpoint))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load the AWS config: %w", err)
	}
	// A custom endpoint has no bucket host names.
	pathStyle := aws.ToString(cfg.BaseEndpoint) != ""
	s3c := s3.NewFromConfig(cfg, func(so *s3.Options) { so.UsePathStyle = pathStyle })
	return &Client{
		region:  o.Region,
		ec2:     ec2.NewFromConfig(cfg),
		s3:      s3c,
		presign: s3.NewPresignClient(s3c),
	}, nil
}
