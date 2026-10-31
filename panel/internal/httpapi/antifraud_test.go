package httpapi

import (
	"context"
	"salfetka/panel/internal/antifraud"
	"salfetka/panel/internal/identity"
	"testing"
)

type fakeAntifraud struct {
	reads, releases int
	actor           string
	readHook        func()
	releaseErr      error
}

func (f *fakeAntifraud) Read(context.Context, string) (antifraud.Page, error) {
	f.reads++
	if f.readHook != nil {
		f.readHook()
	}
	return antifraud.Page{Items: []antifraud.Account{}}, nil
}
func (f *fakeAntifraud) Release(_ context.Context, account string, incident int64, actor string) (bool, error) {
	f.releases++
	f.actor = actor
	return true, f.releaseErr
}
func TestAntifraudRolesCSRFDeliveryAndRelease(t *testing.T) {
	f := newFixture(t)
	owner := f.owner(t)
	a := f.handler.(*api)
	backend := &fakeAntifraud{}
	a.config.Antifraud = backend
	path := "/api/v1/antifraud/accounts"
	release := "/api/v1/antifraud/release"
	body := `{"account_id":"a","incident_id":12}`
	status(t, call(f.handler, "GET", path, "", nil, nil), 401)
	status(t, call(f.handler, "GET", path, "", &owner, nil), 200)
	for _, r := range []identity.Role{identity.Support, identity.Auditor, identity.InfrastructureOperator, identity.AccessOperator} {
		if _, e := f.store.CreateAdmin(context.Background(), owner.Token, string(r), testPassword, r); e != nil {
			t.Fatal(e)
		}
		s, e := f.store.Login(context.Background(), string(r), testPassword, string(r))
		if e != nil {
			t.Fatal(e)
		}
		want := 200
		if r == identity.InfrastructureOperator || r == identity.AccessOperator {
			want = 403
		}
		status(t, call(f.handler, "GET", path, "", &s, nil), want)
		status(t, call(f.handler, "POST", release, body, &s, nil), 403)
	}
	for _, headers := range []map[string]string{{"Origin": "https://evil.invalid"}, {"X-CSRF-Token": "bad"}} {
		status(t, call(f.handler, "POST", release, body, &owner, headers), 403)
	}
	for _, bad := range []string{`{"account_id":"a","incident_id":12,"actor":"someone"}`, `{"account_id":"a","incident_id":0}`, `{"account_id":"a","account_id":"b","incident_id":12}`} {
		status(t, call(f.handler, "POST", release, bad, &owner, nil), 400)
	}
	if backend.releases != 0 {
		t.Fatal("forbidden mutation reached backend")
	}
	status(t, call(f.handler, "POST", release, body, &owner, nil), 200)
	if backend.releases != 1 || backend.actor != owner.User.ID {
		t.Fatal("lost authenticated actor")
	}
	backend.releaseErr = antifraud.ErrConflict
	status(t, call(f.handler, "POST", release, body, &owner, nil), 409)
	for _, query := range []string{"?url=x", "?after=a&after=b", "?after=%xx", "?after=../bad"} {
		status(t, call(f.handler, "GET", path+query, "", &owner, nil), 400)
	}
	a.config.DeliveryOnly = true
	status(t, call(f.handler, "GET", path, "", &owner, nil), 404)
	a.config.DeliveryOnly = false
	a.config.Antifraud = nil
	status(t, call(f.handler, "GET", path, "", &owner, nil), 503)
	a.config.Antifraud = backend
	backend.readHook = func() {
		if e := f.store.Logout(context.Background(), owner.Token, false); e != nil {
			t.Fatal(e)
		}
	}
	status(t, call(f.handler, "GET", path, "", &owner, nil), 401)
}
