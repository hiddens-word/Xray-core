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

// Validator stores valid Shadowsocks users, caches AEAD ciphers, and provides user validation.
type Validator struct {
	sync.RWMutex
	users     map[string]*protocol.MemoryUser
	aeadCache sync.Map // Concurrent map to store AEAD ciphers

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

	if v.users == nil {
		v.users = make(map[string]*protocol.MemoryUser)
	}

	email := strings.ToLower(u.Email)
	if _, exists := v.users[email]; exists {
		return newError("User already exists.")
	}

	v.users[email] = u
	// No need to modify the AEAD cache or behaviorSeed on Add

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
	user, found := v.users[email]
	if !found {
		return newError("User ", email, " not found.")
	}

	delete(v.users, email)

	// Clear all associated AEAD ciphers from the cache for this user
	account := user.Account.(*MemoryAccount)
	v.aeadCache.Range(func(key, value interface{}) bool {
		subkey := key.(string)
		if strings.HasPrefix(subkey, string(account.Key)) {
			v.aeadCache.Delete(subkey)
		}
		return true
	})

	// Recompute behaviorSeed if it has been fused
	if v.behaviorFused {
		v.behaviorSeed = v.computeBehaviorSeed()
	}

	return nil
}

// Get a Shadowsocks user.
// ... Existing Get method logic ...

// GetBehaviorSeed returns the behavior seed.
func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	if !v.behaviorFused {
		v.behaviorFused = true
		v.behaviorSeed = v.computeBehaviorSeed()
	}
	return v.behaviorSeed
}

// computeBehaviorSeed computes a new behavior seed based on the current users' keys.
func (v *Validator) computeBehaviorSeed() uint64 {
	var seed uint64
	for _, user := range v.users {
		account := user.Account.(*MemoryAccount)
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		seed = crc64.Update(seed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}
	return seed
}

func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()

	for _, user := range v.users {
		account := user.Account.(*MemoryAccount)
		if account.Cipher.IsAEAD() {
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]
			subkey := make([]byte, aeadCipher.KeyBytes)
			// Use hkdfSHA1 to derive a subkey from the user's key and the IV.
			hkdfSHA1(account.Key, iv, subkey)

			// Retrieve or create an AEAD instance from the cache.
			aead, err = v.GetOrCreateAEAD(subkey, account)
			if err != nil {
				return nil, nil, nil, 0, err
			}

			// Use the AEAD instance to decrypt the payload.
			var payload []byte
			switch command {
			case protocol.RequestCommandTCP:
				payload = bs[ivLen : ivLen+18] // Adjust length as needed for your protocol.
			case protocol.RequestCommandUDP:
				payload = bs[ivLen:] // Adjust as necessary for UDP payload.
			default:
				err = newError("unsupported command")
				return
			}

			ret, err = aead.Open(nil, iv, payload, nil)
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

// NewAEAD creates a new AEAD cipher based on the given subkey and account.
func NewAEAD(subkey []byte, account *MemoryAccount) (cipher.AEAD, error) {
	aeadCipher := account.Cipher.(*AEADCipher)
	return aeadCipher.AEADAuthCreator(subkey), nil
}

// GetOrCreateAEAD attempts to retrieve an AEAD cipher from cache or creates a new one if not present.
func (v *Validator) GetOrCreateAEAD(subkey []byte, account *MemoryAccount) (cipher.AEAD, error) {
	cacheKey := string(subkey)
	if val, ok := v.aeadCache.Load(cacheKey); ok {
		return val.(cipher.AEAD), nil
	}
	aead, err := NewAEAD(subkey, account)
	if err != nil {
		return nil, err
	}
	v.aeadCache.Store(cacheKey, aead)
	return aead, nil
}
