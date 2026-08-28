package app

import "errors"

// ErrNotFound represents an object not found error
var ErrNotFound = errors.New("object not found")

// InvitePlaceholder represents the placeholder used by members to invite other users
var InvitePlaceholder = "%invite%"

// ErrUserIDRequired is used when OAuth integration returns an empty user ID
var ErrUserIDRequired = errors.New("UserID is required during OAuth integration")

// ErrEmailTaken is returned when an insert violates the per-tenant email uniqueness constraint
var ErrEmailTaken = errors.New("email address is already in use")

type key string

func createKey(name string) key {
	return key("FIDER_CTX_" + name)
}

const (
	//FacebookProvider is const for 'facebook'
	FacebookProvider = "facebook"
	//GoogleProvider is const for 'google'
	GoogleProvider = "google"
	//GitHubProvider is const for 'github'
	GitHubProvider = "github"
)

// Mobile API paths. Registered in routes.go and matched in middleware; a shared
// constant keeps the two in sync.
const (
	MobileSignInPath  = "/widget/signin"
	MobileSignOutPath = "/widget/signout"
)

var (
	RequestCtxKey     = createKey("REQUEST")
	MobileApiCtxKey   = createKey("MOBILE_API")
	AppCheckCtxKey    = createKey("APP_CHECK")
	TransactionCtxKey = createKey("TRANSACTION")
	TenantCtxKey      = createKey("TENANT")
	LocaleCtxKey      = createKey("LOCALE")
	UserCtxKey        = createKey("USER")
	LogPropsCtxKey    = createKey("LOG_PROPS")
)
