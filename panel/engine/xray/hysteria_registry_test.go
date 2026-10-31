package xrayengine

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHysteriaAdmissionRemovalAndLateCleanup(t *testing.T) {
	for n := 0; n < 50; n++ {
		v := account.NewValidator()
		user, _ := (&protocol.User{Email: users[0].Email, Account: serial.ToTypedMessage(&account.Account{Auth: users[0].Secret})}).ToMemoryUser()
		if err := v.Add(user); err != nil {
			t.Fatal(err)
		}
		var admitted, closed atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if u, _ := v.AuthenticateAndTrack(users[0].Secret, func() { closed.Add(1) }); u != nil {
					admitted.Add(1)
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; v.DelByEmail(user.Email) }()
		close(start)
		wg.Wait()
		if admitted.Load() != closed.Load() {
			t.Fatal("carrier escaped revoke")
		}
		if u, _ := v.AuthenticateAndTrack(users[0].Secret, func() {}); u != nil {
			t.Fatal("denied credential admitted")
		}
	}
	v := account.NewValidator()
	user, _ := (&protocol.User{Email: users[0].Email, Account: serial.ToTypedMessage(&account.Account{Auth: users[0].Secret})}).ToMemoryUser()
	v.Add(user)
	entered, finish := make(chan struct{}), make(chan struct{})
	_, cleanup := v.AuthenticateAndTrack(users[0].Secret, func() { close(entered); <-finish })
	done := make(chan struct{})
	go func() { v.DelByEmail(user.Email); close(done) }()
	<-entered
	next, _ := (&protocol.User{Email: user.Email, Account: serial.ToTypedMessage(&account.Account{Auth: users[0].Secret})}).ToMemoryUser()
	if err := v.Add(next); err != nil {
		t.Fatal(err)
	}
	var newClosed atomic.Int64
	_, release := v.AuthenticateAndTrack(users[0].Secret, func() { newClosed.Add(1) })
	cleanup()
	close(finish)
	<-done
	if newClosed.Load() != 0 {
		t.Fatal("old teardown touched replacement")
	}
	v.DelByEmail(user.Email)
	release()
	if newClosed.Load() != 1 {
		t.Fatal("replacement escaped revoke")
	}
}
