package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	stderrors "errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/getfider/fider/app"

	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/services/blob"

	"github.com/getfider/fider/app/pkg/bus"
)

// DefaultClient is an S3 Client
var DefaultClient *s3.Client

func init() {
	bus.Register(Service{})
}

type Service struct{}

func (s Service) Name() string {
	return "S3"
}

func (s Service) Category() string {
	return "blobstorage"
}

func (s Service) Enabled() bool {
	return env.Config.BlobStorage.Type == "s3"
}

func (s Service) Init() {
	s3EnvConfig := env.Config.BlobStorage.S3
	if s3EnvConfig.EndpointURL != "" {
		awsConfig, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(s3EnvConfig.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				s3EnvConfig.AccessKeyID,
				s3EnvConfig.SecretAccessKey,
				"",
			)),
		)
		if err != nil {
			panic(err)
		}

		DefaultClient = s3.NewFromConfig(awsConfig, func(options *s3.Options) {
			options.BaseEndpoint = aws.String(s3EnvConfig.EndpointURL)
			options.UsePathStyle = true
		})
	}

	bus.AddHandler(listBlobs)
	bus.AddHandler(getBlobByKey)
	bus.AddHandler(storeBlob)
	bus.AddHandler(deleteBlob)
}

func listBlobs(ctx context.Context, q *query.ListBlobs) error {
	prefix := basePath(ctx, q.Prefix)
	response, err := DefaultClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(env.Config.BlobStorage.S3.BucketName),
		MaxKeys: aws.Int32(1000),
		Prefix:  aws.String(prefix),
	})
	if err != nil {
		return wrap(err, "failed to list blobs from S3")
	}

	if response.IsTruncated != nil && *response.IsTruncated {
		return wrap(err, "failed to return list of blobs because it was truncated")
	}

	files := make([]string, 0)
	for _, item := range response.Contents {
		key := *item.Key

		// if it ends with '/' it's not an actual blob
		if strings.HasSuffix(key, "/") {
			continue
		}

		fullKey := q.Prefix + key[len(prefix):]
		files = append(files, strings.TrimLeft(fullKey, "/"))
	}

	sort.Strings(files)
	q.Result = files
	return nil
}

func getBlobByKey(ctx context.Context, q *query.GetBlobByKey) error {
	if err := blob.ValidateKey(q.Key); err != nil {
		return wrap(err, "failed to validate blob key '%s'", q.Key)
	}

	resp, err := DefaultClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Config.BlobStorage.S3.BucketName),
		Key:    aws.String(keyFullPathURL(ctx, q.Key)),
	})
	if err != nil {
		if isNotFound(err) {
			return wrap(blob.ErrNotFound, "unable to find blob '%s' on S3", q.Key)
		}
		return wrap(err, "failed to get blob '%s' from S3", q.Key)
	}
	defer func() { _ = resp.Body.Close() }()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return wrap(err, "failed to read blob body '%s' from S3", q.Key)
	}

	q.Result = &dto.Blob{
		Content:     bytes,
		ContentType: *resp.ContentType,
		Size:        *resp.ContentLength,
	}
	return nil
}

func storeBlob(ctx context.Context, c *cmd.StoreBlob) error {
	if err := blob.ValidateKey(c.Key); err != nil {
		return wrap(err, "failed to validate blob key '%s'", c.Key)
	}

	reader := bytes.NewReader(c.Content)
	_, err := DefaultClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(env.Config.BlobStorage.S3.BucketName),
		Key:         aws.String(keyFullPathURL(ctx, c.Key)),
		ContentType: aws.String(c.ContentType),
		ACL:         types.ObjectCannedACLPrivate,
		Body:        reader,
	})
	if err != nil {
		return wrap(err, "failed to upload blob '%s' to S3", c.Key)
	}
	return nil
}

func deleteBlob(ctx context.Context, c *cmd.DeleteBlob) error {
	_, err := DefaultClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Config.BlobStorage.S3.BucketName),
		Key:    aws.String(keyFullPathURL(ctx, c.Key)),
	})
	if err != nil && !isNotFound(err) {
		return wrap(err, "failed to delete blob '%s' from S3", c.Key)
	}
	return nil
}

func keyFullPathURL(ctx context.Context, key string) string {
	return path.Join(basePath(ctx, ""), key)
}

func basePath(ctx context.Context, segment string) string {
	blob.EnsureAuthorizedPrefix(ctx, segment)

	tenant, ok := ctx.Value(app.TenantCtxKey).(*entity.Tenant)
	if ok {
		return fmt.Sprintf("tenants/%s/%s", strconv.Itoa(tenant.ID), segment)
	}
	return segment
}

func isNotFound(err error) bool {
	var apiErr smithy.APIError
	return stderrors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchKey"
}

func wrap(err error, format string, a ...any) error {
	return errors.Wrap(err, format, a...)
}
