package web

import (
	"strings"

	"github.com/getfider/fider/app/pkg/errors"
)

// BearerToken extracts the token from an "Authorization: Bearer <token>" header value.
func BearerToken(authorization string) (string, error) {
	const prefix = "Bearer "

	auth := strings.TrimSpace(authorization)
	if !strings.HasPrefix(auth, prefix) {
		return "", errors.New("missing bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}