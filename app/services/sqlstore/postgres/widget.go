package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/dbx"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/services/sqlstore/dbEntities"
)

func createWidgetToken(ctx context.Context, c *cmd.CreateWidgetToken) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		rawToken := entity.GenerateWidgetToken()
		hash := entity.HashWidgetToken(rawToken)

		var id int
		if err := trx.Get(&id,
			"INSERT INTO widget_tokens (tenant_id, token_hash, label, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
			tenant.ID, hash, strings.TrimSpace(c.Label), time.Now()); err != nil {
			return errors.Wrap(err, "failed to create widget token")
		}

		c.Result = &entity.WidgetToken{
			ID:    id,
			Label: strings.TrimSpace(c.Label),
			Hash:  hash,
		}

		// The raw token is only available in the response once, at creation.
		c.Result.RawToken = rawToken
		return nil
	})
}

func revokeWidgetToken(ctx context.Context, c *cmd.RevokeWidgetToken) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		if _, err := trx.Execute(
			"UPDATE widget_tokens SET revoked_at = $3 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
			c.TokenID, tenant.ID, time.Now()); err != nil {
			return errors.Wrap(err, "failed to revoke widget token")
		}
		return nil
	})
}

func updateWidgetTokenLastUsed(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		if _, err := trx.Execute(
			"UPDATE widget_tokens SET last_used_at = $3 WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL",
			tenant.ID, c.Hash, time.Now()); err != nil {
			return errors.Wrap(err, "failed to update widget token last used")
		}
		return nil
	})
}

func listWidgetTokens(ctx context.Context, q *query.ListWidgetTokens) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		var tokens []*dbEntities.WidgetToken
		if err := trx.Select(&tokens, `
			SELECT id, label, token_hash, created_at, last_used_at, revoked_at
			FROM widget_tokens
			WHERE tenant_id = $1
			ORDER BY created_at`, tenant.ID); err != nil {
			return errors.Wrap(err, "failed to list widget tokens")
		}

		q.Result = make([]*entity.WidgetToken, len(tokens))
		for i, token := range tokens {
			q.Result[i] = token.ToModel()
		}
		return nil
	})
}

func getWidgetTokenByHash(ctx context.Context, q *query.GetWidgetTokenByHash) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		var token dbEntities.WidgetToken
		if err := trx.Get(&token, `
			SELECT id, label, token_hash, created_at, last_used_at, revoked_at
			FROM widget_tokens
			WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL`,
			tenant.ID, q.Hash); err != nil {
			return errors.Wrap(err, "failed to get widget token by hash")
		}
		q.Result = token.ToModel()
		return nil
	})
}

func getUserByDeviceHash(ctx context.Context, q *query.GetUserByDeviceHash) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		result, err := queryUser(ctx, trx, "device_hash = $1 AND tenant_id = $2", q.DeviceHash, tenant.ID)
		if err != nil {
			return errors.Wrap(err, "failed to get device user")
		}
		q.Result = result
		return nil
	})
}

func registerDeviceUser(ctx context.Context, c *cmd.RegisterDeviceUser) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		name := strings.TrimSpace(c.Name)
		email := strings.ToLower(strings.TrimSpace(c.Email))

		id, _, err := insertUser(trx, tenant, name, email, enum.RoleVisitor, c.DeviceHash)
		c.Created = err == nil
		if err != nil && errors.Cause(err) != app.ErrNotFound {
			return errors.Wrap(err, "failed to register device user")
		}

		if c.Created {
			registered, err := queryUser(ctx, trx, "id = $1 AND tenant_id = $2", id, tenant.ID)
			if err != nil {
				return errors.Wrap(err, "failed to load registered device user")
			}
			c.Result = registered
			return nil
		}

		existing, err := queryUser(ctx, trx, "device_hash = $1 AND tenant_id = $2", c.DeviceHash, tenant.ID)
		if err != nil {
			return errors.Wrap(err, "failed to load existing device user")
		}
		c.Result = existing
		return nil
	})
}