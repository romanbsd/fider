package web

import (
	"strings"

	"github.com/getfider/fider/app/pkg/errors"
)

// BearerToken extracts the token from an "Authorization: Bearer <token>" header value.
func BearerToken(authorization string) (string, error) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("missing bearer token")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}