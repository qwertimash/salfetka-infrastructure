package httpapi

import (
	"context"
	"encoding/json"
	"salfetka/panel/internal/identity"
	"testing"
)

type diagnosticReadFunc func(context.Context, string, string) (json.RawMessage, error)

func (f diagnosticReadFunc) Read(ctx context.Context, t, b string) (json.RawMessage, error) {
	return f(ctx, t, b)
}
func TestDiagnosticsRBACDeliveryAndRevokedSession(t *testing.T) {
	f := newFixture(t)
	owner := f.owner(t)
	a := f.handler.(*api)
	calls := 0
	a.config.Diagnostics = diagnosticReadFunc(func(context.Context, string, string) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"testers":[]}`), nil
	})
	path := "/api/v1/diagnostics/testers"
	status(t, call(f.handler, "GET", path, "", nil, nil), 401)
	status(t, call(f.handler, "GET", path, "", &owner, nil), 200)
	for _, r := range []identity.Role{identity.Support, identity.Auditor, identity.InfrastructureOperator, identity.AccessOperator} {
		_, err := f.store.CreateAdmin(context.Background(), owner.Token, string(r), testPassword, r)
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.Login(context.Background(), string(r), testPassword, string(r))
		if err != nil {
			t.Fatal(err)
		}
		want := 200
		if r == identity.AccessOperator {
			want = 403
		}
		status(t, call(f.handler, "GET", path, "", &s, nil), want)
	}
	before := calls
	for _, path := range []string{path + "?before=x", path + "/../testers", path + "?url=https://evil.invalid", path + "?before=x&before=y"} {
		status(t, call(f.handler, "GET", path, "", &owner, nil), 400)
	}
	if calls != before {
		t.Fatal("invalid query reached collector")
	}
	a.config.DeliveryOnly = true
	status(t, call(f.handler, "GET", path, "", &owner, nil), 404)
	a.config.DeliveryOnly = false
	status(t, call(f.handler, "POST", path, "{}", &owner, nil), 405)
	a.config.Diagnostics = nil
	status(t, call(f.handler, "GET", path, "", &owner, nil), 503)
	a.config.Diagnostics = diagnosticReadFunc(func(context.Context, string, string) (json.RawMessage, error) {
		if err := f.store.Logout(context.Background(), owner.Token, false); err != nil {
			t.Fatal(err)
		}
		return json.RawMessage(`{"testers":[]}`), nil
	})
	status(t, call(f.handler, "GET", path, "", &owner, nil), 401)
}
