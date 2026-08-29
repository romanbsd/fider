package firebase

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/publickeys"
	jwtgo "github.com/golang-jwt/jwt/v4"
)

const (
	ModeOff     = "off"
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"

	appCheckJWKSURL = "https://firebaseappcheck.googleapis.com/v1/jwks"
	authCertsURL    = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	appCheckMaxTTL  = 6 * time.Hour
)

var (
	ErrDisabled      = stderrors.New("firebase authentication is not enabled")
	ErrMissingToken  = stderrors.New("firebase app check token is missing")
	ErrInvalidToken  = stderrors.New("firebase token is invalid")
	ErrDisallowedApp = stderrors.New("firebase app is not allowed")
)

type AppCheckClaims struct {
	AppID string
}

type AuthClaims struct {
	UID           string
	Name          string
	Email         string
	EmailVerified bool
	Anonymous     bool
}

type Verifier interface {
	VerifyAppCheck(context.Context, string) (*AppCheckClaims, error)
	VerifyIDToken(context.Context, string) (*AuthClaims, error)
}

type jwtVerifier struct {
	projectID     string
	projectNumber string
	appIDs        map[string]struct{}
	appCheckKeys  *publickeys.Source
	authKeys      *publickeys.Source
	now           func() time.Time
}

type verifierConfig struct {
	projectID       string
	projectNumber   string
	appIDs          map[string]struct{}
	appCheckJWKSURL string
	authCertsURL    string
	httpClient      *http.Client
	now             func() time.Time
}

var (
	verifierMu sync.RWMutex
	verifier   Verifier
)

func Mode() string {
	return strings.ToLower(strings.TrimSpace(env.Config.Widget.Firebase.AppCheckMode))
}

func Enabled() bool {
	return Mode() != ModeOff
}

func Initialize(ctx context.Context) error {
	mode := Mode()
	if mode != ModeOff && mode != ModeMonitor && mode != ModeEnforce {
		return fmt.Errorf("invalid APP_CHECK_MODE %q", env.Config.Widget.Firebase.AppCheckMode)
	}
	if mode == ModeOff {
		setVerifier(nil)
		return nil
	}

	projectID := strings.TrimSpace(env.Config.Widget.Firebase.ProjectID)
	if projectID == "" {
		return fmt.Errorf("FIREBASE_PROJECT_ID is required when App Check is enabled")
	}
	projectNumber := strings.TrimSpace(env.Config.Widget.Firebase.ProjectNumber)
	if !isProjectNumber(projectNumber) {
		return fmt.Errorf("FIREBASE_PROJECT_NUMBER must contain only digits when App Check is enabled")
	}

	appIDs := parseAppIDs(env.Config.Widget.Firebase.AppIDs)
	if len(appIDs) == 0 {
		return fmt.Errorf("FIREBASE_APP_IDS must contain at least one app ID when App Check is enabled")
	}

	// Preserve the existing fail-fast startup behavior by fetching App Check's
	// public signing keys before accepting traffic. Firebase Auth keys remain
	// lazy because its client has always fetched them on first verification.
	initCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	v := newJWTVerifier(verifierConfig{
		projectID:       projectID,
		projectNumber:   projectNumber,
		appIDs:          appIDs,
		appCheckJWKSURL: appCheckJWKSURL,
		authCertsURL:    authCertsURL,
	})
	if err := v.appCheckKeys.Warm(initCtx); err != nil {
		return fmt.Errorf("initialize Firebase App Check verifier: %w", err)
	}

	setVerifier(v)
	return nil
}

func VerifyAppCheck(ctx context.Context, rawToken string) (*AppCheckClaims, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, ErrMissingToken
	}
	v := currentVerifier()
	if v == nil {
		return nil, ErrDisabled
	}
	return v.VerifyAppCheck(ctx, rawToken)
}

func VerifyIDToken(ctx context.Context, rawToken string) (*AuthClaims, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, ErrInvalidToken
	}
	v := currentVerifier()
	if v == nil {
		return nil, ErrDisabled
	}
	return v.VerifyIDToken(ctx, rawToken)
}

func SetVerifierForTest(v Verifier) func() {
	verifierMu.Lock()
	previous := verifier
	verifier = v
	verifierMu.Unlock()
	return func() { setVerifier(previous) }
}

func newJWTVerifier(cfg verifierConfig) *jwtVerifier {
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &jwtVerifier{
		projectID:     cfg.projectID,
		projectNumber: cfg.projectNumber,
		appIDs:        cfg.appIDs,
		appCheckKeys: publickeys.NewJWKS(cfg.appCheckJWKSURL, publickeys.Options{
			HTTPClient: cfg.httpClient,
			MaxTTL:     appCheckMaxTTL,
			Now:        now,
		}),
		authKeys: publickeys.NewX509(cfg.authCertsURL, publickeys.Options{
			HTTPClient: cfg.httpClient,
			Now:        now,
		}),
		now: now,
	}
}

func (v *jwtVerifier) VerifyAppCheck(ctx context.Context, rawToken string) (*AppCheckClaims, error) {
	token, claims, err := parseSignedToken(ctx, rawToken, v.appCheckKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if token.Header["typ"] != "JWT" {
		return nil, fmt.Errorf("%w: App Check token has invalid type", ErrInvalidToken)
	}
	if issuer, ok := claims["iss"].(string); !ok || issuer != "https://firebaseappcheck.googleapis.com/"+v.projectNumber {
		return nil, fmt.Errorf("%w: App Check token has invalid issuer", ErrInvalidToken)
	}
	if !audienceContains(claims["aud"], "projects/"+v.projectNumber) {
		return nil, fmt.Errorf("%w: App Check token has invalid audience", ErrInvalidToken)
	}
	if !numericDateAfter(claims["exp"], v.now()) {
		return nil, fmt.Errorf("%w: App Check token is expired or missing expiration", ErrInvalidToken)
	}
	appID, ok := claims["sub"].(string)
	if !ok || appID == "" {
		return nil, fmt.Errorf("%w: App Check token has empty subject", ErrInvalidToken)
	}
	if !v.allowsApp(appID) {
		return nil, ErrDisallowedApp
	}
	return &AppCheckClaims{AppID: appID}, nil
}

func (v *jwtVerifier) allowsApp(appID string) bool {
	_, ok := v.appIDs[appID]
	return ok
}

func (v *jwtVerifier) VerifyIDToken(ctx context.Context, rawToken string) (*AuthClaims, error) {
	_, claims, err := parseSignedToken(ctx, rawToken, v.authKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if audience, ok := claims["aud"].(string); !ok || audience != v.projectID {
		return nil, fmt.Errorf("%w: Firebase Auth token has invalid audience", ErrInvalidToken)
	}
	if issuer, ok := claims["iss"].(string); !ok || issuer != "https://securetoken.google.com/"+v.projectID {
		return nil, fmt.Errorf("%w: Firebase Auth token has invalid issuer", ErrInvalidToken)
	}
	if !numericDateAfter(claims["exp"], v.now()) {
		return nil, fmt.Errorf("%w: Firebase Auth token is expired or missing expiration", ErrInvalidToken)
	}
	if !numericDateBefore(claims["iat"], v.now()) {
		return nil, fmt.Errorf("%w: Firebase Auth token has invalid issued-at time", ErrInvalidToken)
	}
	if !numericDateBefore(claims["auth_time"], v.now()) {
		return nil, fmt.Errorf("%w: Firebase Auth token has invalid authentication time", ErrInvalidToken)
	}
	uid, ok := claims["sub"].(string)
	if !ok || uid == "" || len(uid) > 128 {
		return nil, fmt.Errorf("%w: Firebase Auth token has invalid subject", ErrInvalidToken)
	}

	result := &AuthClaims{UID: uid}
	if firebaseClaims, ok := claims["firebase"].(map[string]any); ok {
		result.Anonymous = firebaseClaims["sign_in_provider"] == "anonymous"
	}
	if name, ok := claims["name"].(string); ok {
		result.Name = name
	}
	if email, ok := claims["email"].(string); ok {
		result.Email = email
	}
	if verified, ok := claims["email_verified"].(bool); ok {
		result.EmailVerified = verified
	}
	return result, nil
}

func parseSignedToken(ctx context.Context, rawToken string, keys *publickeys.Source) (*jwtgo.Token, jwtgo.MapClaims, error) {
	parser := jwtgo.NewParser(jwtgo.WithValidMethods([]string{"RS256"}), jwtgo.WithJSONNumber(), jwtgo.WithoutClaimsValidation())
	token, err := parser.Parse(rawToken, func(token *jwtgo.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token has no key ID")
		}
		return keys.Key(ctx, kid)
	})
	if err != nil {
		return nil, nil, err
	}
	claims, ok := token.Claims.(jwtgo.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, fmt.Errorf("token claims are invalid")
	}
	return token, claims, nil
}

func audienceContains(raw any, expected string) bool {
	audience, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range audience {
		if value, ok := item.(string); ok && value == expected {
			return true
		}
	}
	return false
}

func numericDateAfter(raw any, now time.Time) bool {
	seconds, ok := numericDate(raw)
	return ok && seconds > float64(now.Unix())
}

func numericDateBefore(raw any, now time.Time) bool {
	seconds, ok := numericDate(raw)
	return ok && seconds < float64(now.Unix())
}

func numericDate(raw any) (float64, bool) {
	switch value := raw.(type) {
	case json.Number:
		seconds, err := value.Float64()
		return seconds, err == nil
	case float64:
		return value, true
	default:
		return 0, false
	}
}

func isProjectNumber(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseAppIDs(raw string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		if appID := strings.TrimSpace(item); appID != "" {
			result[appID] = struct{}{}
		}
	}
	return result
}

func currentVerifier() Verifier {
	verifierMu.RLock()
	defer verifierMu.RUnlock()
	return verifier
}

func setVerifier(v Verifier) {
	verifierMu.Lock()
	defer verifierMu.Unlock()
	verifier = v
}
