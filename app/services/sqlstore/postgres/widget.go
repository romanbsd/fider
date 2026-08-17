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
		now := time.Now()

		var id int
		if err := trx.Get(&id,
			"INSERT INTO widget_tokens (tenant_id, token_hash, label, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
			tenant.ID, hash, strings.TrimSpace(c.Label), now); err != nil {
			return errors.Wrap(err, "failed to create widget token")
		}

		c.Result = &entity.WidgetToken{
			ID:        id,
			Label:     strings.TrimSpace(c.Label),
			Hash:      hash,
			CreatedAt: now,
		}

		// The raw token is only available in the response once, at creation.
		c.Result.RawToken = rawToken
		return nil
	})
}

func revokeWidgetToken(ctx context.Context, c *cmd.RevokeWidgetToken) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		rows, err := trx.Execute(
			"UPDATE widget_tokens SET revoked_at = $3 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
			c.TokenID, tenant.ID, time.Now())
		if err != nil {
			return errors.Wrap(err, "failed to revoke widget token")
		}
		if rows == 0 {
			return app.ErrNotFound
		}
		return nil
	})
}

func updateWidgetTokenLastUsed(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		var token dbEntities.WidgetToken
		if err := trx.Get(&token, `
			UPDATE widget_tokens SET last_used_at = $3
			WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL
			RETURNING id, label, token_hash, created_at, last_used_at, revoked_at`,
			tenant.ID, c.Hash, time.Now()); err != nil {
			return errors.Wrap(err, "failed to update widget token last used")
		}
		c.Result = token.ToModel()
		return nil
	})
}

func listWidgetTokens(ctx context.Context, q *query.ListWidgetTokens) error {
	return using(ctx, func(trx *dbx.Trx, tenant *entity.Tenant, user *entity.User) error {
		var tokens []*dbEntities.WidgetToken
		if err := trx.Select(&tokens, `
			SELECT id, label, token_hash, created_at, last_used_at, revoked_at
			FROM widget_tokens
			WHERE tenant_id = $1 AND revoked_at IS NULL
			ORDER BY created_at, id`, tenant.ID); err != nil {
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

		// A savepoint lets us recover from insertUser's constraint violation
		// below without aborting the rest of this transaction (Postgres
		// aborts the whole transaction after any failed statement until a
		// ROLLBACK, full or to a savepoint).
		if _, err := trx.Execute("SAVEPOINT device_email_retry"); err != nil {
			return errors.Wrap(err, "failed to register device user")
		}

		newSecret := entity.GenerateDeviceSecret()
		id, _, err := insertUser(trx, tenant, name, email, enum.RoleVisitor, c.DeviceHash, entity.HashDeviceSecret(newSecret))
		if err != nil && errors.Cause(err) == app.ErrEmailTaken {
			// Email is only a cosmetic display field for device-registered
			// Visitor users (device_hash is the real identity). Surfacing this
			// collision distinguishably from an invalid-token failure would let
			// a widget-token holder enumerate registered emails by probing
			// arbitrary udid/email pairs, so register the device without the
			// email instead of failing the request.
			if _, rbErr := trx.Execute("ROLLBACK TO SAVEPOINT device_email_retry"); rbErr != nil {
				return errors.Wrap(rbErr, "failed to register device user")
			}
			id, _, err = insertUser(trx, tenant, name, "", enum.RoleVisitor, c.DeviceHash, entity.HashDeviceSecret(newSecret))
		}
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
			c.NewDeviceSecret = newSecret
			return nil
		}

		existing, err := queryUser(ctx, trx, "device_hash = $1 AND tenant_id = $2", c.DeviceHash, tenant.ID)
		if err != nil {
			return errors.Wrap(err, "failed to load existing device user")
		}

		// Re-authenticating an existing device requires proof of possession of
		// the secret issued at its first registration: the tenant-wide widget
		// token alone (already validated by the caller before dispatching this
		// command) is not enough, since every legitimate device of the tenant
		// shares it. Without this check, a token holder could authenticate as
		// any other known device_hash.
		if existing.DeviceSecretHash == "" || c.DeviceSecret == "" ||
			entity.HashDeviceSecret(c.DeviceSecret) != existing.DeviceSecretHash {
			return app.ErrDeviceSecretMismatch
		}

		// A blocked device user must not be handed a fresh session at sign-in
		// either — the same rule authenticateWidget enforces for widget-header
		// requests. The JWT would be rejected on every later request anyway, but
		// failing here keeps sign-in honest ("blocked users are unable to sign
		// in") instead of returning a token that can never be used.
		if existing.Status == enum.UserBlocked {
			return app.ErrNotFound
		}

		c.Result = existing
		return nil
	})
}
