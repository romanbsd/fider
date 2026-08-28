package firebase

import "context"

// StubVerifier is a scriptable Verifier for tests. Configure the claims or
// errors each method should return; zero-valued fields return nil.
type StubVerifier struct {
	AppCheckClaims *AppCheckClaims
	AuthClaims     *AuthClaims
	AppCheckErr    error
	AuthErr        error
}

func (v StubVerifier) VerifyAppCheck(context.Context, string) (*AppCheckClaims, error) {
	return v.AppCheckClaims, v.AppCheckErr
}

func (v StubVerifier) VerifyIDToken(context.Context, string) (*AuthClaims, error) {
	return v.AuthClaims, v.AuthErr
}
