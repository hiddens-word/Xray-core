package http

import (
	_ "strings"
	"sync"
	//"fmt"
	"github.com/hiddens-word/xray-core/common/protocol"
	"strings"
)

// Validator stores valid trojan users.
type Validator struct {
	// Considering email's usage here, map + sync.Mutex/RWMutex may have better performance.
	emails   sync.Map
	acconuns sync.Map
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u.Email != "" {
		_, loaded := v.emails.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return newError("User ", u.Email, " already exists.")
		}
	}
	v.acconuns.Store(u.Account.(*Account).Username, u.Account.(*Account).Password)
	return nil
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(e string) error {
	if e == "" {
		return newError("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.emails.Load(le)
	if u == nil {
		return newError("User ", e, " not found.")
	}
	v.emails.Delete(le)

	a, _ := v.acconuns.Load(le)
	if a == nil {
		return newError("Account", e, " not found.")
	}
	v.acconuns.Delete(le)
	return nil
}

func (v *Validator) HasAccount(username, password string) bool {
	p, ok := v.acconuns.Load(username)
	if !ok {
		return false
	}
	return p == password
}
