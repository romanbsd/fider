package awsses

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/log"
	"github.com/getfider/fider/app/services/email"
)

var sesClient *sesv2.Client

func init() {
	bus.Register(Service{})
}

type Service struct{}

func (s Service) Name() string {
	return "AWSSES"
}

func (s Service) Category() string {
	return "email"
}

func (s Service) Enabled() bool {
	return env.Config.Email.Type == "awsses"
}

func (s Service) Init() {
	sesEnvConfig := env.Config.Email.AWSSES
	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(sesEnvConfig.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			sesEnvConfig.AccessKeyID,
			sesEnvConfig.SecretAccessKey,
			"",
		)),
	)
	if err != nil {
		panic(err)
	}

	sesClient = sesv2.NewFromConfig(awsConfig)
	bus.AddListener(sendMail)
	bus.AddHandler(fetchRecentSupressions)
}

func sendMail(ctx context.Context, c *cmd.SendMail) {
	if c.Props == nil {
		c.Props = dto.Props{}
	}

	if c.From.Address == "" {
		c.From.Address = email.NoReply
	}

	for _, to := range c.To {
		if to.Address == "" {
			return
		}

		if !email.CanSendTo(to.Address) {
			log.Warnf(ctx, "Skipping email to '@{Name} <@{Address}>'.", dto.Props{
				"Name":    to.Name,
				"Address": to.Address,
			})
			return
		}

		log.Debugf(ctx, "Sending email to @{Address} with template @{TemplateName} and params @{Props}.", dto.Props{
			"Address":      to.Address,
			"TemplateName": c.TemplateName,
			"Props":        to.Props,
		})

		message := email.RenderMessage(ctx, c.TemplateName, c.From.Address, c.Props.Merge(to.Props))
		tags := []types.MessageTag{
			{Name: aws.String("template"), Value: aws.String(c.TemplateName)},
		}

		tenant, ok := ctx.Value(app.TenantCtxKey).(*entity.Tenant)
		if ok && !env.IsSingleHostMode() {
			tags = append(tags, types.MessageTag{Name: aws.String("tenant"), Value: aws.String(tenant.Subdomain)})
		}

		input := &sesv2.SendEmailInput{
			FromEmailAddress: aws.String(c.From.String()),
			Destination: &types.Destination{
				ToAddresses: []string{to.String()},
			},
			Content: &types.EmailContent{
				Simple: &types.Message{
					Body: &types.Body{
						Html: &types.Content{
							Charset: aws.String("UTF-8"),
							Data:    aws.String(message.Body),
						},
					},
					Subject: &types.Content{
						Charset: aws.String("UTF-8"),
						Data:    aws.String(email.EncodeSubject(message.Subject)),
					},
				},
			},
			EmailTags: tags,
		}

		result, err := sesClient.SendEmail(ctx, input)
		if err != nil {
			panic(errors.Wrap(err, "failed to send email with template %s", c.TemplateName))
		}

		log.Debugf(ctx, "Email sent with ID @{MessageId}.", dto.Props{
			"MessageId": *result.MessageId,
		})
	}
}

func fetchRecentSupressions(ctx context.Context, q *query.FetchRecentSupressions) error {
	response, err := sesClient.ListSuppressedDestinations(ctx, &sesv2.ListSuppressedDestinationsInput{
		StartDate: aws.Time(q.StartTime),
		PageSize:  aws.Int32(1000),
	})
	if err != nil {
		return errors.Wrap(err, "failed to list supressed destinations")
	}

	q.EmailAddresses = make([]string, 0)
	for _, destination := range response.SuppressedDestinationSummaries {
		q.EmailAddresses = append(q.EmailAddresses, *destination.EmailAddress)
	}
	return nil
}
