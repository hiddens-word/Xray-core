package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"github.com/xtls/xray-core/common/protocol"
	"hash/crc64"
	"strings"
	"sync"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users map[string]*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = newError("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return newError("The cipher is not support Single-port Multi-user")
	}

	// Initialize the map if it's nil
	if v.users == nil {
		v.users = make(map[string]*protocol.MemoryUser)
	}

	// Ensure email is in lowercase
	email := strings.ToLower(u.Email)
	if _, exists := v.users[email]; exists {
		// If the user already exists, return an error
		return newError("User already exists.")
	}

	// Add the user to the map
	v.users[email] = u

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return newError("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	if _, found := v.users[email]; !found {
		return newError("User ", email, " not found.")
	}

	delete(v.users, email)

	return nil
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()

	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			switch command {
			case protocol.RequestCommandTCP:
				data := make([]byte, 4+aead.NonceSize())
				ret, err = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				data := make([]byte, 8192)
				ret, err = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			if err == nil {
				u = user
				err = account.CheckIV(iv)
				return
			}
		} else {
			// The following line is commented out because Non-AEAD ciphers might not use an IV.
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			return
		}
	}

	err = ErrNotFound
	return
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	if !v.behaviorFused {
		v.behaviorFused = true
		if v.behaviorSeed == 0 {
			for _, user := range v.users {
				account := user.Account.(*MemoryAccount)
				hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
				hashkdf.Write(account.Key)
				v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
			}
		}
	}
	return v.behaviorSeed
}
