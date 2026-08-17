package idtoken

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/getfider/fider/app/pkg/errors"
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

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// keySetTTL bounds how long a fetched JWKS is trusted before the provider key
// set is refreshed.
const keySetTTL = time.Hour

// Validator verifies identity provider tokens signed by a JWKS endpoint.
// The keyset is fetched lazily and refreshed periodically or when a token
// references an unknown key, so provider key rotation is picked up without a
// process restart.
type Validator struct {
	cfg      Config
	client   *http.Client
	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	lastLoad time.Time
}

// New creates a Validator for the given provider configuration
func New(cfg Config) *Validator {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	return &Validator{cfg: cfg, client: client, keys: make(map[string]*rsa.PublicKey)}
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
	emailVerified, _ := claims["email_verified"].(bool)

	return &Claims{
		UserID:        sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
	}, nil
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

func (v *Validator) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Serve from cache while the key set is fresh.
	if key, ok := v.keys[kid]; ok && time.Since(v.lastLoad) < keySetTTL {
		return key, nil
	}

	// Refresh on an unknown kid or a stale key set so provider key rotation is
	// picked up without a restart. The key set is replaced only after a
	// successful fetch, so removed keys stop validating tokens. A failed refresh
	// fails closed: a stale key is never served past its TTL.
	if err := v.fetchKeys(ctx); err != nil {
		return nil, err
	}

	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, errors.New("identity provider keyset does not contain a key matching '%s'", kid)
}

func (v *Validator) fetchKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return errors.Wrap(err, "failed to build keyset request")
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to fetch identity provider keyset")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to fetch identity provider keyset: unexpected status code %d", resp.StatusCode)
	}

	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return errors.Wrap(err, "failed to parse identity provider keyset")
	}

	fresh := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, key := range set.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pub, err := decodeRSAPublicKey(key)
		if err != nil {
			continue
		}
		fresh[key.Kid] = pub
	}

	if len(fresh) == 0 {
		return errors.New("identity provider keyset did not contain any usable keys")
	}

	v.keys = fresh
	v.lastLoad = time.Now()
	return nil
}

func decodeRSAPublicKey(key jwk) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	if len(exponent) == 0 {
		return nil, errors.New("empty RSA exponent")
	}

	exp := 0
	for _, b := range exponent {
		exp = exp<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: exp,
	}, nil
}