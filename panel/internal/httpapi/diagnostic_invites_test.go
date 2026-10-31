package httpapi

import (
	"context"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/diagnostics"
	"salfetka/panel/internal/identity"
	"testing"
)

type inviteFunc func(context.Context, string, string, string) (diagnostics.Invitation, error)

func (f inviteFunc) Invite(c context.Context, a, n, k string) (diagnostics.Invitation, error) {
	return f(c, a, n, k)
}
func TestDiagnosticInviteOwnerOnlyConsentSeparate(t *testing.T) {
	f := newFixture(t)
	owner := f.owner(t)
	a := f.handler.(*api)
	user, _ := database.NewID()
	if _, e := f.pool.Exec(context.Background(), "INSERT INTO access_users(id,name) VALUES($1,'Diagnostic account')", user); e != nil {
		t.Fatal(e)
	}
	body := `{"user_id":"` + user + `"}`
	path := "/api/v1/diagnostics/invitations"
	key := "diagnostic-invite-test-001"
	status(t, call(f.handler, "POST", path, body, &owner, accessHeaders(0, key)), 503)
	calls := 0
	a.config.DiagnosticsInviter = inviteFunc(func(_ context.Context, account, name, request string) (diagnostics.Invitation, error) {
		calls++
		if account != user || name != "Diagnostic account" || request != owner.User.ID+":"+key {
			t.Error("wrong target")
		}
		return diagnostics.Invitation{Code: "synthetic", TesterID: user, ExpiresAtMS: 1}, nil
	})
	status(t, call(f.handler, "POST", path, body, &owner, accessHeaders(0, key)), 200)
	for _, r := range []identity.Role{identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor} {
		if _, e := f.store.CreateAdmin(context.Background(), owner.Token, string(r), testPassword, r); e != nil {
			t.Fatal(e)
		}
		s, e := f.store.Login(context.Background(), string(r), testPassword, string(r))
		if e != nil {
			t.Fatal(e)
		}
		status(t, call(f.handler, "POST", path, body, &s, accessHeaders(0, key)), 403)
	}
	status(t, call(f.handler, "POST", path, body, &owner, map[string]string{"X-CSRF-Token": ""}), 403)
	if calls != 1 {
		t.Fatal("unauthorized invitation")
	}
	var devices int
	f.pool.QueryRow(context.Background(), "SELECT count(*) FROM access_devices WHERE user_id=$1", user).Scan(&devices)
	if devices != 0 {
		t.Fatal("implicit VPN enrollment")
	}
	a.config.DeliveryOnly = true
	status(t, call(f.handler, "POST", path, body, &owner, accessHeaders(0, key)), 404)
	a.config.DeliveryOnly = false
	a.config.DiagnosticsInviter = inviteFunc(func(context.Context, string, string, string) (diagnostics.Invitation, error) {
		if e := f.store.Logout(context.Background(), owner.Token, false); e != nil {
			t.Fatal(e)
		}
		return diagnostics.Invitation{Code: "never-return"}, nil
	})
	w := call(f.handler, "POST", path, body, &owner, accessHeaders(0, key))
	status(t, w, 401)
	if w.Body.String() == "never-return" {
		t.Fatal("revoked session got code")
	}
}
