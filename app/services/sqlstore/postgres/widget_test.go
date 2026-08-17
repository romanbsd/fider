package postgres_test

import (
	"context"
	"net/url"
	"sync"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/dbx"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/web"

	. "github.com/getfider/fider/app/pkg/assert"
)

func TestWidgetTokenStorage_Create(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	create := &cmd.CreateWidgetToken{Label: "My Website"}
	err := bus.Dispatch(demoTenantCtx, create)
	Expect(err).IsNil()
	Expect(create.Result.ID > 0).IsTrue()
	Expect(create.Result.RawToken).HasLen(32)
	Expect(create.Result.Hash).HasLen(64)
	Expect(create.Result.Label).Equals("My Website")
	Expect(create.Result.RevokedAt).IsNil()
	Expect(create.Result.CreatedAt.IsZero()).IsFalse()

	// only the hash is persisted, never the raw token
	getByHash := &query.GetWidgetTokenByHash{Hash: entity.HashWidgetToken(create.Result.RawToken)}
	err = bus.Dispatch(demoTenantCtx, getByHash)
	Expect(err).IsNil()
	Expect(getByHash.Result.ID).Equals(create.Result.ID)
	Expect(getByHash.Result.Label).Equals("My Website")
	Expect(getByHash.Result.RawToken).IsEmpty()
	Expect(getByHash.Result.Hash).Equals(entity.HashWidgetToken(create.Result.RawToken))
}

func TestWidgetTokenStorage_Revoke(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	create := &cmd.CreateWidgetToken{Label: "Temp Token"}
	err := bus.Dispatch(demoTenantCtx, create)
	Expect(err).IsNil()

	getByHash := &query.GetWidgetTokenByHash{Hash: entity.HashWidgetToken(create.Result.RawToken)}
	err = bus.Dispatch(demoTenantCtx, getByHash)
	Expect(err).IsNil()

	revoke := &cmd.RevokeWidgetToken{TokenID: create.Result.ID}
	err = bus.Dispatch(demoTenantCtx, revoke)
	Expect(err).IsNil()

	getByHash = &query.GetWidgetTokenByHash{Hash: entity.HashWidgetToken(create.Result.RawToken)}
	err = bus.Dispatch(demoTenantCtx, getByHash)
	Expect(errors.Cause(err)).Equals(app.ErrNotFound)
	Expect(getByHash.Result).IsNil()
}

func TestWidgetTokenStorage_LastUsed(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	create := &cmd.CreateWidgetToken{Label: "Usage Token"}
	err := bus.Dispatch(demoTenantCtx, create)
	Expect(err).IsNil()
	Expect(create.Result.LastUsedAt).IsNil()

	touch := &cmd.UpdateWidgetTokenLastUsed{Hash: entity.HashWidgetToken(create.Result.RawToken)}
	err = bus.Dispatch(demoTenantCtx, touch)
	Expect(err).IsNil()
	Expect(touch.Result.LastUsedAt).IsNotNil()

	getByHash := &query.GetWidgetTokenByHash{Hash: entity.HashWidgetToken(create.Result.RawToken)}
	err = bus.Dispatch(demoTenantCtx, getByHash)
	Expect(err).IsNil()
	Expect(getByHash.Result.LastUsedAt).IsNotNil()
}

func TestWidgetTokenStorage_List(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	first := &cmd.CreateWidgetToken{Label: "One"}
	second := &cmd.CreateWidgetToken{Label: "Two"}
	err := bus.Dispatch(demoTenantCtx, first, second)
	Expect(err).IsNil()

	list := &query.ListWidgetTokens{}
	err = bus.Dispatch(demoTenantCtx, list)
	Expect(err).IsNil()
	Expect(list.Result).HasLen(2)
	Expect(list.Result[0].Label).Equals("One")
	Expect(list.Result[1].Label).Equals("Two")

	// revoking a token excludes it from subsequent lists
	revoke := &cmd.RevokeWidgetToken{TokenID: first.Result.ID}
	err = bus.Dispatch(demoTenantCtx, revoke)
	Expect(err).IsNil()

	list = &query.ListWidgetTokens{}
	err = bus.Dispatch(demoTenantCtx, list)
	Expect(err).IsNil()
	Expect(list.Result).HasLen(1)
	Expect(list.Result[0].Label).Equals("Two")
}

func TestWidgetTokenStorage_DeviceUser(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	register := &cmd.RegisterDeviceUser{DeviceHash: "device-123", Name: "Jane Device", Email: "jane@device.io"}
	err := bus.Dispatch(demoTenantCtx, register)
	Expect(err).IsNil()
	Expect(register.Created).IsTrue()
	Expect(register.Result.ID > 0).IsTrue()
	Expect(register.Result.Name).Equals("Jane Device")
	Expect(register.Result.Email).Equals("")
	Expect(register.NewDeviceSecret).NotEquals("")

	// re-authenticating the same device without the secret issued at its
	// first registration is rejected: the shared tenant widget token alone
	// (validated upstream of this command) must not be enough to
	// authenticate as an arbitrary known device_hash
	noSecret := &cmd.RegisterDeviceUser{DeviceHash: "device-123", Name: "Jane Device", Email: "jane@device.io"}
	err = bus.Dispatch(demoTenantCtx, noSecret)
	Expect(errors.Cause(err)).Equals(app.ErrDeviceSecretMismatch)

	wrongSecret := &cmd.RegisterDeviceUser{DeviceHash: "device-123", Name: "Jane Device", Email: "jane@device.io", DeviceSecret: "not-the-right-secret"}
	err = bus.Dispatch(demoTenantCtx, wrongSecret)
	Expect(errors.Cause(err)).Equals(app.ErrDeviceSecretMismatch)

	// same device hash + correct secret reuses the same user
	again := &cmd.RegisterDeviceUser{DeviceHash: "device-123", Name: "Jane Device", Email: "jane@device.io", DeviceSecret: register.NewDeviceSecret}
	err = bus.Dispatch(demoTenantCtx, again)
	Expect(err).IsNil()
	Expect(again.Created).IsFalse()
	Expect(again.Result.ID).Equals(register.Result.ID)
	Expect(again.NewDeviceSecret).Equals("")

	// a different device hash creates a distinct user
	other := &cmd.RegisterDeviceUser{DeviceHash: "device-456", Name: "John Device", Email: "john@device.io"}
	err = bus.Dispatch(demoTenantCtx, other)
	Expect(err).IsNil()
	Expect(other.Created).IsTrue()
	Expect(other.Result.ID).NotEquals(register.Result.ID)

	getByDevice := &query.GetUserByDeviceHash{DeviceHash: "device-456"}
	err = bus.Dispatch(demoTenantCtx, getByDevice)
	Expect(err).IsNil()
	Expect(getByDevice.Result.ID).Equals(other.Result.ID)

	getUnknown := &query.GetUserByDeviceHash{DeviceHash: "device-unknown"}
	err = bus.Dispatch(demoTenantCtx, getUnknown)
	Expect(errors.Cause(err)).Equals(app.ErrNotFound)
	Expect(getUnknown.Result).IsNil()
}

func TestWidgetTokenStorage_DeviceUser_DoesNotPersistEmail(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	register := &cmd.RegisterDeviceUser{
		DeviceHash: "device-email-squat",
		Name:       "Squatter",
		Email:      "victim@got.com",
	}
	err := bus.Dispatch(demoTenantCtx, register)
	Expect(err).IsNil()
	Expect(register.Result.Email).Equals("")

	// OAuth, magic-link and invite lookup must not resolve a device user by a
	// client-supplied email — otherwise a widget-token holder can squat an
	// unused address and later take over the real person's account.
	byEmail := &query.GetUserByEmail{Email: "victim@got.com"}
	err = bus.Dispatch(demoTenantCtx, byEmail)
	Expect(errors.Cause(err)).Equals(app.ErrNotFound)
	Expect(byEmail.Result).IsNil()
}

func TestWidgetTokenStorage_DeviceUser_EmailCollision(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	first := &cmd.RegisterDeviceUser{DeviceHash: "device-collide-1", Name: "First Device", Email: "collide@device.io"}
	err := bus.Dispatch(demoTenantCtx, first)
	Expect(err).IsNil()
	Expect(first.Result.Email).Equals("")

	// A second, different device registering with the same email must still
	// succeed (email is not stored for device users) instead of failing with a
	// distinguishable error a widget-token holder could use to enumerate
	// registered emails.
	second := &cmd.RegisterDeviceUser{DeviceHash: "device-collide-2", Name: "Second Device", Email: "collide@device.io"}
	err = bus.Dispatch(demoTenantCtx, second)
	Expect(err).IsNil()
	Expect(second.Created).IsTrue()
	Expect(second.Result.Email).Equals("")
	Expect(second.Result.ID).NotEquals(first.Result.ID)
}

// TestWidgetTokenStorage_DeviceUser_ConcurrentFirstRegistration documents
// and guards the outcome when two requests race a device's very first
// registration (e.g. a client's own retried request, or a caller replaying
// a known/guessed device_hash before its legitimate owner ever registers):
// insertUser's ON CONFLICT (tenant_id, device_hash) DO NOTHING already makes
// this deterministic at the database level — exactly one request wins and
// gets the device secret, every other one gets a clean
// app.ErrDeviceSecretMismatch (since it presented no secret for what the
// database now considers an existing device), never a torn/corrupted row.
//
// ponytail: this does NOT give the losing caller any way to recover the
// winner's identity — inherent to a bare device_hash claim. Malicious
// exploitation requires knowing a specific target's device_hash before its
// first-ever use, which for a properly random UUID v4 udid (as documented)
// is computationally infeasible; the same assumption the existing
// docs/MOBILE_FEEDBACK_API.md security notes already rely on. Closing the
// remaining self-race (a client's own duplicate first-launch request)
// requires a client-supplied idempotency token, a bigger protocol change,
// upgrade if this proves to matter in practice.
//
// Unlike every other test in this file, each goroutine here uses its own
// connection/transaction: the shared per-test transaction (demoTenantCtx)
// can't be used concurrently (Postgres doesn't support concurrent use of one
// connection), so this commits directly and cleans up manually instead of
// relying on TeardownDatabaseTest's rollback.
func TestWidgetTokenStorage_DeviceUser_ConcurrentFirstRegistration(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	u, _ := url.Parse("http://cdn.test.fider.io")
	base := context.WithValue(context.Background(), app.RequestCtxKey, web.Request{URL: u})

	t.Cleanup(func() {
		cleanup, _ := dbx.BeginTx(base)
		_, _ = cleanup.Execute("DELETE FROM users WHERE device_hash = $1", "device-race")
		cleanup.MustCommit()
	})

	const concurrency = 8
	results := make([]*cmd.RegisterDeviceUser, concurrency)
	errs := make([]error, concurrency)

	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			connTrx, err := dbx.BeginTx(base)
			if err != nil {
				errs[i] = err
				return
			}
			ctx := withTenant(context.WithValue(base, app.TransactionCtxKey, connTrx), demoTenant)

			c := &cmd.RegisterDeviceUser{DeviceHash: "device-race", Name: "Racer"}
			errs[i] = bus.Dispatch(ctx, c)
			results[i] = c
			if errs[i] == nil {
				connTrx.MustCommit()
			} else {
				connTrx.MustRollback()
			}
		}(i)
	}
	wg.Wait()

	winners := 0
	var winnerID int
	for i := range concurrency {
		if errs[i] == nil {
			winners++
			Expect(results[i].Created).IsTrue()
			Expect(results[i].NewDeviceSecret).NotEquals("")
			winnerID = results[i].Result.ID
		} else {
			Expect(errors.Cause(errs[i])).Equals(app.ErrDeviceSecretMismatch)
		}
	}
	Expect(winners).Equals(1)

	getByDevice := &query.GetUserByDeviceHash{DeviceHash: "device-race"}
	err := bus.Dispatch(demoTenantCtx, getByDevice)
	Expect(err).IsNil()
	Expect(getByDevice.Result.ID).Equals(winnerID)
}
