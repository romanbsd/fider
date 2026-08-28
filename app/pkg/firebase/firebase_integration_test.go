package firebase

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRealFirebaseTokens is an opt-in smoke test for short-lived tokens from a
// real Firebase test project. Tokens are read only from the environment and are
// never logged or stored as fixtures.
func TestRealFirebaseTokens(t *testing.T) {
	projectID := os.Getenv("FIREBASE_TEST_PROJECT_ID")
	projectNumber := os.Getenv("FIREBASE_TEST_PROJECT_NUMBER")
	appIDs := os.Getenv("FIREBASE_TEST_APP_IDS")
	appCheckToken := os.Getenv("FIREBASE_TEST_APP_CHECK_TOKEN")
	authToken := os.Getenv("FIREBASE_TEST_AUTH_ID_TOKEN")
	if projectID == "" || projectNumber == "" || appIDs == "" || appCheckToken == "" || authToken == "" {
		t.Skip("real Firebase token environment is not configured")
	}

	verifier := newJWTVerifier(verifierConfig{
		projectID:       projectID,
		projectNumber:   projectNumber,
		appIDs:          parseAppIDs(appIDs),
		appCheckJWKSURL: appCheckJWKSURL,
		authCertsURL:    authCertsURL,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := verifier.VerifyAppCheck(ctx, appCheckToken); err != nil {
		t.Fatal("real App Check token verification failed")
	}
	if _, err := verifier.VerifyIDToken(ctx, authToken); err != nil {
		t.Fatal("real Firebase Auth token verification failed")
	}
}
