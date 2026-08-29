package firebase

import (
	"context"
	stderrors "errors"
	"testing"

	. "github.com/getfider/fider/app/pkg/assert"
)

func TestVerifyAppCheck_RejectsMissingTokenBeforeVerifier(t *testing.T) {
	RegisterT(t)
	defer SetVerifierForTest(StubVerifier{AppCheckClaims: &AppCheckClaims{AppID: "unexpected"}})()

	claims, err := VerifyAppCheck(context.Background(), "")
	Expect(stderrors.Is(err, ErrMissingToken)).IsTrue()
	Expect(claims).IsNil()
}

func TestVerifyIDToken_ReturnsVerifierClaims(t *testing.T) {
	RegisterT(t)
	expected := &AuthClaims{UID: "firebase-user", Anonymous: true}
	defer SetVerifierForTest(StubVerifier{AuthClaims: expected})()

	claims, err := VerifyIDToken(context.Background(), "token")
	Expect(err).IsNil()
	Expect(claims.UID).Equals("firebase-user")
	Expect(claims.Anonymous).IsTrue()
}

func TestParseAppIDs_TrimsAndDropsEmptyValues(t *testing.T) {
	RegisterT(t)
	ids := parseAppIDs(" app-1,app-2, app-1, ")
	Expect(ids).HasLen(2)
	_, hasFirst := ids["app-1"]
	_, hasSecond := ids["app-2"]
	Expect(hasFirst).IsTrue()
	Expect(hasSecond).IsTrue()
}

func TestJWTVerifier_AllowsOnlyConfiguredFirebaseAppIDs(t *testing.T) {
	RegisterT(t)
	verifier := &jwtVerifier{appIDs: parseAppIDs("android-app,ios-app")}

	Expect(verifier.allowsApp("android-app")).IsTrue()
	Expect(verifier.allowsApp("unknown-app")).IsFalse()
}
