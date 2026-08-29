package idtoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/publickeys"
	jwtgo "github.com/golang-jwt/jwt/v4"

	. "github.com/getfider/fider/app/pkg/assert"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "client-123"
	testKid      = "key-1"
)

type testJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

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
			Keys []testJWK `json:"keys"`
		}{
			Keys: []testJWK{
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

func TestValidator_EmailVerified_AcceptedForms(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		value any
	}{
		{"boolean true", true},
		{"string true", "true"},
		{"string uppercase True", "True"},
	} {
		claims, err := validator.Verify(ctx, signToken(priv, func(c jwtgo.MapClaims) {
			c["email_verified"] = tc.value
		}))
		Expect(err).IsNil()
		Expect(claims.EmailVerified).IsTrue()
	}

	for _, tc := range []struct {
		name  string
		value any
	}{
		{"boolean false", false},
		{"string false", "false"},
		{"malformed", "yes"},
		{"number", 1},
	} {
		claims, err := validator.Verify(ctx, signToken(priv, func(c jwtgo.MapClaims) {
			c["email_verified"] = tc.value
		}))
		Expect(err).IsNil()
		Expect(claims.EmailVerified).IsFalse()
	}
}

func TestValidator_EmailVerified_Missing(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	claims, err := validator.Verify(context.Background(), signToken(priv, func(c jwtgo.MapClaims) {
		delete(c, "email_verified")
	}))
	Expect(err).IsNil()
	Expect(claims.EmailVerified).IsFalse()
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

func TestValidator_MissingExp(t *testing.T) {
	RegisterT(t)
	validator, priv := newValidator(t)

	_, err := validator.Verify(context.Background(), signToken(priv, func(c jwtgo.MapClaims) {
		delete(c, "exp")
	}))
	Expect(err).IsNotNil()
	Expect(errors.Cause(err).Error()).ContainsSubstring("expiration")
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

func TestValidator_KeyRotation(t *testing.T) {
	RegisterT(t)

	priv1, pub1 := generateTestKeys()
	priv2, pub2 := generateTestKeys()

	var (
		mu   sync.Mutex
		keys = map[string]*rsa.PublicKey{"key-1": pub1}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		encoded := make([]testJWK, 0, len(keys))
		for kid, pub := range keys {
			encoded = append(encoded, testJWK{
				Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
				N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E: base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			})
		}
		_ = json.NewEncoder(w).Encode(struct {
			Keys []testJWK `json:"keys"`
		}{Keys: encoded})
	}))
	t.Cleanup(server.Close)

	validator := New(Config{JWKSURL: server.URL, Issuer: testIssuer, ClientID: testAudience})

	signWith := func(kid string, priv *rsa.PrivateKey) string {
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
			"iss":            testIssuer,
			"aud":            testAudience,
			"sub":            "user-subject-1",
			"email":          "jane@example.com",
			"email_verified": true,
			"name":           "Jane Doe",
			"exp":            time.Now().Add(15 * time.Minute).Unix(),
		})
		token.Header["kid"] = kid
		signed, err := token.SignedString(priv)
		Expect(err).IsNil()
		return signed
	}

	ctx := context.Background()

	// token signed with the initially published key verifies
	_, err := validator.Verify(ctx, signWith("key-1", priv1))
	Expect(err).IsNil()

	// provider rotates to a new key: token signed with the new key must verify
	// without a restart
	mu.Lock()
	keys = map[string]*rsa.PublicKey{"key-2": pub2}
	mu.Unlock()

	_, err = validator.Verify(ctx, signWith("key-2", priv2))
	Expect(err).IsNil()

	// the removed key must no longer validate tokens
	_, err = validator.Verify(ctx, signWith("key-1", priv1))
	Expect(err).IsNotNil()
	Expect(errors.Cause(err).Error()).ContainsSubstring("keyset does not contain")
}

func TestValidator_RefreshFailure_FailsClosed(t *testing.T) {
	RegisterT(t)

	priv, pub := generateTestKeys()
	var down = false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		jwksHandler(pub)(w, r)
	}))
	t.Cleanup(server.Close)

	now := time.Now()
	validator := &Validator{
		cfg: Config{JWKSURL: server.URL, Issuer: testIssuer, ClientID: testAudience},
		keys: publickeys.NewJWKS(server.URL, publickeys.Options{
			FixedTTL: keySetTTL,
			Now:      func() time.Time { return now },
		}),
	}
	signed := signToken(priv, nil)

	// initial fetch works
	_, err := validator.Verify(context.Background(), signed)
	Expect(err).IsNil()

	// past the key-set TTL the validator must refresh; a failing refresh must
	// fail closed rather than keep trusting the cached (possibly rotated-away) key
	now = now.Add(2 * keySetTTL)
	down = true

	_, err = validator.Verify(context.Background(), signed)
	Expect(err).IsNotNil()
}

// TestValidator_ConcurrentUnknownKid_CoalescesFetch guards against a DoS where
// an unauthenticated caller submits tokens with distinct unknown kids: each
// miss used to refresh the JWKS while holding the validator-wide mutex for
// the whole (up to client-timeout) HTTP call, serializing every other
// verification — including for unrelated tenants — behind it. Concurrent
// misses must now share a single in-flight fetch instead.
func TestValidator_ConcurrentUnknownKid_CoalescesFetch(t *testing.T) {
	RegisterT(t)

	priv, pub := generateTestKeys()

	var (
		mu      sync.Mutex
		hits    int
		release = make(chan struct{})
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		<-release // hold every concurrent caller here until the test releases them
		jwksHandler(pub)(w, r)
	}))
	t.Cleanup(server.Close)

	validator := New(Config{JWKSURL: server.URL, Issuer: testIssuer, ClientID: testAudience})
	signed := signToken(priv, nil)

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrency)
	for i := range concurrency {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = validator.Verify(context.Background(), signed)
		}(i)
	}

	// give every goroutine a chance to reach the (blocked) HTTP handler before
	// releasing it, so a non-coalesced implementation would have already
	// issued its own separate request by now
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for _, err := range errs {
		Expect(err).IsNil()
	}

	mu.Lock()
	defer mu.Unlock()
	Expect(hits).Equals(1)
}

// TestValidator_LeaderContextCancelled_DoesNotAbortSharedRefresh guards
// against passing a caller-specific context into the coalesced fetch:
// whichever caller happens to be the singleflight leader is arbitrary, so if
// its context were used, cancelling that one request (e.g. a disconnected
// client) would abort the in-flight HTTP call and fail every other
// coalesced caller too — including unrelated tenants' sign-ins. The shared
// fetch must run independent of any single caller's context.
func TestValidator_LeaderContextCancelled_DoesNotAbortSharedRefresh(t *testing.T) {
	RegisterT(t)

	_, pub := generateTestKeys()

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		jwksHandler(pub)(w, r)
	}))
	t.Cleanup(server.Close)

	validator := New(Config{JWKSURL: server.URL, Issuer: testIssuer, ClientID: testAudience})

	const concurrency = 5
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	cancellableCtx, cancel := context.WithCancel(context.Background())
	for i := range concurrency {
		wg.Add(1)
		ctx := context.Background()
		if i == 0 {
			ctx = cancellableCtx // the caller whose context we'll cancel mid-fetch
		}
		go func(i int) {
			defer wg.Done()
			_, errs[i] = validator.getKey(ctx, testKid)
		}(i)
	}

	// give every goroutine a chance to join the same in-flight fetch before
	// cancelling one of their contexts
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for _, err := range errs {
		Expect(err).IsNil()
	}
}
