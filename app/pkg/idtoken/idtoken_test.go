package idtoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getfider/fider/app/pkg/errors"
	jwtgo "github.com/golang-jwt/jwt/v4"

	. "github.com/getfider/fider/app/pkg/assert"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "client-123"
	testKid      = "key-1"
)

func generateTestKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func jwksHandler(pub *rsa.PublicKey) http.HandlerFunc {
	modulus := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})

	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			Keys []jwk `json:"keys"`
		}{
			Keys: []jwk{
				{Kty: "RSA", Kid: testKid, Use: "sig", Alg: "RS256", N: modulus, E: exponent},
			},
		})
	}
}

func signToken(priv *rsa.PrivateKey, overrides func(claims jwtgo.MapClaims)) string {
	claims := jwtgo.MapClaims{
		"iss":            testIssuer,
		"aud":            testAudience,
		"sub":            "user-subject-1",
		"email":          "jane@example.com",
		"email_verified": true,
		"name":           "Jane Doe",
		"exp":            time.Now().Add(15 * time.Minute).Unix(),
	}
	if overrides != nil {
		overrides(claims)
	}

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = testKid
	signed, err := token.SignedString(priv)
	if err != nil {
		panic(err)
	}
	return signed
}

func newValidator(t *testing.T) (*Validator, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := generateTestKeys()
	server := httptest.NewServer(jwksHandler(pub))
	t.Cleanup(server.Close)

	validator := New(Config{
		JWKSURL:  server.URL,
		Issuer:   testIssuer,
		ClientID: testAudience,
	})
	return validator, priv
}

func TestValidator_Verify(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	ctx := context.Background()
	claims, err := validator.Verify(ctx, signToken(priv, nil))
	Expect(err).IsNil()
	Expect(claims.UserID).Equals("user-subject-1")
	Expect(claims.Email).Equals("jane@example.com")
	Expect(claims.EmailVerified).IsTrue()
	Expect(claims.Name).Equals("Jane Doe")
}

func TestValidator_WrongAudience(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	_, err := validator.Verify(context.Background(), signToken(priv, func(c jwtgo.MapClaims) {
		c["aud"] = "other-client"
	}))
	Expect(err).IsNotNil()
	Expect(errors.Cause(err).Error()).ContainsSubstring("audience")
}

func TestValidator_WrongIssuer(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	_, err := validator.Verify(context.Background(), signToken(priv, func(c jwtgo.MapClaims) {
		c["iss"] = "https://evil.example.com"
	}))
	Expect(err).IsNotNil()
	Expect(errors.Cause(err).Error()).ContainsSubstring("issuer")
}

func TestValidator_Expired(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	_, err := validator.Verify(context.Background(), signToken(priv, func(c jwtgo.MapClaims) {
		c["exp"] = time.Now().Add(-15 * time.Minute).Unix()
	}))
	Expect(err).IsNotNil()
}

func TestValidator_UnknownKey(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
		"iss": testIssuer,
		"sub": "user-subject-1",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	token.Header["kid"] = "unknown-key"
	signed, err := token.SignedString(priv)
	Expect(err).IsNil()

	_, err = validator.Verify(context.Background(), signed)
	Expect(err).IsNotNil()
	Expect(errors.Cause(err).Error()).ContainsSubstring("keyset does not contain")
}

func TestValidator_UnacceptableSigningMethod(t *testing.T) {
	RegisterT(t)
	validator, _ := newValidator(t)

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, jwtgo.MapClaims{
		"iss": testIssuer,
		"sub": "user-subject-1",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	token.Header["kid"] = testKid
	signed, err := token.SignedString([]byte("secret"))
	Expect(err).IsNil()

	_, err = validator.Verify(context.Background(), signed)
	Expect(err).IsNotNil()
	Expect(errors.Cause(err).Error()).ContainsSubstring("unexpected signing method")
}

func TestValidator_IsConfigured(t *testing.T) {
	RegisterT(t)

	validator := New(Config{JWKSURL: "https://x", Issuer: "https://y", ClientID: "z"})
	Expect(validator.IsConfigured()).IsTrue()

	empty := New(Config{})
	Expect(empty.IsConfigured()).IsFalse()
}