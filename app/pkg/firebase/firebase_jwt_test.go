package firebase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getfider/fider/app/pkg/env"
	jwtgo "github.com/golang-jwt/jwt/v4"

	. "github.com/getfider/fider/app/pkg/assert"
)

const (
	testProjectID     = "firebase-project"
	testProjectNumber = "1234567890"
	testAppID         = "1:1234567890:ios:abc123"
	testAppCheckKid   = "app-check-key"
	testAuthKid       = "auth-key"
)

type verifierTestFixture struct {
	verifier    *jwtVerifier
	appCheckKey *rsa.PrivateKey
	authKey     *rsa.PrivateKey
	now         time.Time
}

func newVerifierTestFixture(t *testing.T) verifierTestFixture {
	t.Helper()
	appCheckKey := generateRSAKey(t)
	authKey := generateRSAKey(t)
	now := time.Unix(1_700_000_000, 0)

	appCheckServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=21600")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"kid": testAppCheckKid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(appCheckKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	t.Cleanup(appCheckServer.Close)

	certificate := selfSignedCertificate(t, authKey)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]string{testAuthKid: certificate})
	}))
	t.Cleanup(authServer.Close)

	client := appCheckServer.Client()
	return verifierTestFixture{
		verifier: newJWTVerifier(verifierConfig{
			projectID:       testProjectID,
			projectNumber:   testProjectNumber,
			appIDs:          parseAppIDs(testAppID),
			appCheckJWKSURL: appCheckServer.URL,
			authCertsURL:    authServer.URL,
			httpClient:      client,
			now:             func() time.Time { return now },
		}),
		appCheckKey: appCheckKey,
		authKey:     authKey,
		now:         now,
	}
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func selfSignedCertificate(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "firebase-auth-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func signFirebaseToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwtgo.MapClaims) string {
	t.Helper()
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func validAppCheckClaims(now time.Time) jwtgo.MapClaims {
	return jwtgo.MapClaims{
		"iss": "https://firebaseappcheck.googleapis.com/" + testProjectNumber,
		"aud": []string{"projects/" + testProjectNumber},
		"exp": now.Add(time.Hour).Unix(),
		"sub": testAppID,
	}
}

func validAuthClaims(now time.Time) jwtgo.MapClaims {
	return jwtgo.MapClaims{
		"iss":            "https://securetoken.google.com/" + testProjectID,
		"aud":            testProjectID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Add(-time.Minute).Unix(),
		"auth_time":      now.Add(-2 * time.Minute).Unix(),
		"sub":            "firebase-user",
		"name":           "Jane Doe",
		"email":          "jane@example.com",
		"email_verified": true,
		"firebase": map[string]any{
			"sign_in_provider": "anonymous",
		},
	}
}

func TestJWTVerifier_VerifiesAppCheckToken(t *testing.T) {
	RegisterT(t)
	fixture := newVerifierTestFixture(t)
	token := signFirebaseToken(t, fixture.appCheckKey, testAppCheckKid, validAppCheckClaims(fixture.now))

	claims, err := fixture.verifier.VerifyAppCheck(context.Background(), token)
	Expect(err).IsNil()
	Expect(claims.AppID).Equals(testAppID)
}

func TestJWTVerifier_RejectsInvalidAppCheckClaims(t *testing.T) {
	RegisterT(t)
	fixture := newVerifierTestFixture(t)
	tests := []struct {
		name   string
		mutate func(jwtgo.MapClaims)
	}{
		{"wrong issuer", func(c jwtgo.MapClaims) { c["iss"] = "https://firebaseappcheck.googleapis.com/999" }},
		{"project ID audience", func(c jwtgo.MapClaims) { c["aud"] = []string{"projects/" + testProjectID} }},
		{"string audience", func(c jwtgo.MapClaims) { c["aud"] = "projects/" + testProjectNumber }},
		{"expired", func(c jwtgo.MapClaims) { c["exp"] = fixture.now.Add(-time.Second).Unix() }},
		{"missing subject", func(c jwtgo.MapClaims) { delete(c, "sub") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := validAppCheckClaims(fixture.now)
			tc.mutate(claims)
			token := signFirebaseToken(t, fixture.appCheckKey, testAppCheckKid, claims)
			if _, err := fixture.verifier.VerifyAppCheck(context.Background(), token); err == nil {
				t.Fatal("expected invalid App Check token")
			}
		})
	}
}

func TestJWTVerifier_RejectsWrongAppCheckTypeAndDisallowedApp(t *testing.T) {
	RegisterT(t)
	fixture := newVerifierTestFixture(t)

	claims := validAppCheckClaims(fixture.now)
	claims["sub"] = "unlisted-app"
	_, err := fixture.verifier.VerifyAppCheck(context.Background(), signFirebaseToken(t, fixture.appCheckKey, testAppCheckKid, claims))
	Expect(err).Equals(ErrDisallowedApp)

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, validAppCheckClaims(fixture.now))
	token.Header["kid"] = testAppCheckKid
	token.Header["typ"] = "not-jwt"
	signed, signErr := token.SignedString(fixture.appCheckKey)
	Expect(signErr).IsNil()
	_, err = fixture.verifier.VerifyAppCheck(context.Background(), signed)
	Expect(err).IsNotNil()
}

func TestJWTVerifier_VerifiesFirebaseAuthToken(t *testing.T) {
	RegisterT(t)
	fixture := newVerifierTestFixture(t)
	token := signFirebaseToken(t, fixture.authKey, testAuthKid, validAuthClaims(fixture.now))

	claims, err := fixture.verifier.VerifyIDToken(context.Background(), token)
	Expect(err).IsNil()
	Expect(claims.UID).Equals("firebase-user")
	Expect(claims.Name).Equals("Jane Doe")
	Expect(claims.Email).Equals("jane@example.com")
	Expect(claims.EmailVerified).IsTrue()
	Expect(claims.Anonymous).IsTrue()
}

func TestJWTVerifier_RejectsInvalidFirebaseAuthClaims(t *testing.T) {
	fixture := newVerifierTestFixture(t)
	tests := []struct {
		name   string
		mutate func(jwtgo.MapClaims)
	}{
		{"wrong issuer", func(c jwtgo.MapClaims) { c["iss"] = "https://securetoken.google.com/other" }},
		{"array audience", func(c jwtgo.MapClaims) { c["aud"] = []string{testProjectID} }},
		{"expired", func(c jwtgo.MapClaims) { c["exp"] = fixture.now.Add(-time.Second).Unix() }},
		{"future issued at", func(c jwtgo.MapClaims) { c["iat"] = fixture.now.Add(time.Second).Unix() }},
		{"future auth time", func(c jwtgo.MapClaims) { c["auth_time"] = fixture.now.Add(time.Second).Unix() }},
		{"missing auth time", func(c jwtgo.MapClaims) { delete(c, "auth_time") }},
		{"empty subject", func(c jwtgo.MapClaims) { c["sub"] = "" }},
		{"long subject", func(c jwtgo.MapClaims) { c["sub"] = strings.Repeat("x", 129) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := validAuthClaims(fixture.now)
			tc.mutate(claims)
			token := signFirebaseToken(t, fixture.authKey, testAuthKid, claims)
			if _, err := fixture.verifier.VerifyIDToken(context.Background(), token); err == nil {
				t.Fatal("expected invalid Firebase Auth token")
			}
		})
	}
}

func TestInitialize_RequiresNumericProjectNumberWhenEnabled(t *testing.T) {
	RegisterT(t)
	previous := env.Config.Widget.Firebase
	t.Cleanup(func() { env.Config.Widget.Firebase = previous })

	env.Config.Widget.Firebase.AppCheckMode = ModeMonitor
	env.Config.Widget.Firebase.ProjectID = testProjectID
	env.Config.Widget.Firebase.ProjectNumber = "not-a-number"
	env.Config.Widget.Firebase.AppIDs = testAppID
	err := Initialize(context.Background())
	Expect(err).IsNotNil()
	Expect(err.Error()).ContainsSubstring("FIREBASE_PROJECT_NUMBER")
}

func TestIsProjectNumber(t *testing.T) {
	RegisterT(t)
	Expect(isProjectNumber("1234567890")).IsTrue()
	Expect(isProjectNumber("")).IsFalse()
	Expect(isProjectNumber("123-456")).IsFalse()
}
