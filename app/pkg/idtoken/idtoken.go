package idtoken

import (
	"context"
	"strings"
	"time"

	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/publickeys"
	jwtgo "github.com/golang-jwt/jwt/v4"
)

// Claims are the claims expected from an Identity Provider ID token
type Claims struct {
	UserID        string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// Config describes how to verify tokens issued by a provider
type Config struct {
	JWKSURL  string
	Issuer   string
	ClientID string
}

// keySetTTL bounds how long a fetched JWKS is trusted before the provider key
// set is refreshed.
const keySetTTL = time.Hour

// Validator verifies identity provider tokens signed by a JWKS endpoint.
// The keyset is fetched lazily and refreshed periodically or when a token
// references an unknown key, so provider key rotation is picked up without a
// process restart.
type Validator struct {
	cfg  Config
	keys *publickeys.Source
}

// New creates a Validator for the given provider configuration
func New(cfg Config) *Validator {
	return &Validator{
		cfg: cfg,
		keys: publickeys.NewJWKS(cfg.JWKSURL, publickeys.Options{
			FixedTTL: keySetTTL,
		}),
	}
}

// IsConfigured returns true when the provider settings required for validation are present
func (v *Validator) IsConfigured() bool {
	return v.cfg.JWKSURL != "" && v.cfg.Issuer != "" && v.cfg.ClientID != ""
}

// Verify parses, authenticates and validates a provider-issued ID token
func (v *Validator) Verify(ctx context.Context, token string) (*Claims, error) {
	parsed, err := jwtgo.Parse(token, func(t *jwtgo.Token) (any, error) {
		if _, ok := t.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method used by identity provider token")
		}
		return v.getKey(ctx, jwkKid(t))
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify identity provider token")
	}

	claims, ok := parsed.Claims.(jwtgo.MapClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("identity provider token claims are invalid")
	}

	if err := claims.Valid(); err != nil {
		return nil, errors.Wrap(err, "identity provider token claims failed validation")
	}

	if _, ok := claims["exp"]; !ok {
		return nil, errors.New("identity provider token does not have an expiration claim")
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" || issuer != v.cfg.Issuer {
		return nil, errors.New("identity provider token has an unexpected issuer")
	}

	if err := validateAudience(claims, v.cfg.ClientID); err != nil {
		return nil, err
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("identity provider token is missing the subject")
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	return &Claims{
		UserID:        sub,
		Email:         email,
		EmailVerified: parseEmailVerified(claims["email_verified"]),
		Name:          name,
	}, nil
}

// parseEmailVerified accepts Apple's email_verified claim as either a JSON
// boolean true or the string "true" (the Apple web SDK emits the string form).
// Every other representation — missing, false, or malformed — is treated as
// unverified, which the sign-in flow then rejects.
func parseEmailVerified(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

func validateAudience(claims jwtgo.MapClaims, clientID string) error {
	switch aud := claims["aud"].(type) {
	case string:
		if aud != clientID {
			return errors.New("identity provider token audience does not match")
		}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == clientID {
				return nil
			}
		}
		return errors.New("identity provider token audience does not match")
	default:
		return errors.New("identity provider token is missing the audience")
	}
	return nil
}

func jwkKid(t *jwtgo.Token) string {
	kid, _ := t.Header["kid"].(string)
	return kid
}

func (v *Validator) getKey(ctx context.Context, kid string) (any, error) {
	key, err := v.keys.Key(ctx, kid)
	if err != nil {
		return nil, errors.Wrap(err, "identity provider keyset lookup failed")
	}
	return key, nil
}
