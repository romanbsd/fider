package dbEntities

import (
	"database/sql"

	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/pkg/dbx"
)

// WidgetToken is the database mapping for widget_tokens table
type WidgetToken struct {
	ID         sql.NullInt64  `db:"id"`
	Label      sql.NullString `db:"label"`
	Hash       sql.NullString `db:"token_hash"`
	CreatedAt  dbx.NullTime   `db:"created_at"`
	LastUsedAt dbx.NullTime   `db:"last_used_at"`
	RevokedAt  dbx.NullTime   `db:"revoked_at"`
}

func (t *WidgetToken) ToModel() *entity.WidgetToken {
	if t == nil {
		return nil
	}

	token := &entity.WidgetToken{
		ID:    int(t.ID.Int64),
		Label: t.Label.String,
		Hash:  t.Hash.String,
	}
	if t.CreatedAt.Valid {
		token.CreatedAt = t.CreatedAt.Time
	}
	if t.LastUsedAt.Valid {
		token.LastUsedAt = &t.LastUsedAt.Time
	}
	if t.RevokedAt.Valid {
		token.RevokedAt = &t.RevokedAt.Time
	}
	return token
}