package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	lru "github.com/hashicorp/golang-lru"
	"github.com/xtls/xray-core/common/protocol"
	"hash/crc64"
	"strings"
	"sync"
)

const (
	DefaultHotUsersSize = 1000
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	hotUsers  *lru.Cache
	coldUsers map[string]*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = newError("Not Found")

func NewValidator(cacheSize int) (*Validator, error) {
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, err
	}
	return &Validator{
		hotUsers:  cache,
		coldUsers: make(map[string]*protocol.MemoryUser),
	}, nil
}

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.coldUsers) > 0 {
		return newError("The cipher is not support Single-port Multi-user")
	}

	// Initialize the map if it's nil
	if v.coldUsers == nil {
		v.coldUsers = make(map[string]*protocol.MemoryUser)
	}

	// Ensure email is in lowercase
	email := strings.ToLower(u.Email)
	if _, exists := v.coldUsers[email]; exists {
		return newError("User already exists in cold area.")
	}

	// Add the user to the map
	v.coldUsers[email] = u
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

	if v.hotUsers.Contains(email) {
		v.hotUsers.Remove(email)
	}

	if _, found := v.coldUsers[email]; !found {
		return newError("User ", email, " not found.")
	}

	delete(v.coldUsers, email)

	return nil
}

func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()
	// 尝试从热区（LRU缓存）获取用户
	if user, aead, ret, ivLen, err := v.tryDecryptFromCache(bs, command); err == nil {
		return user, aead, ret, ivLen, nil
	}

	// 如果未在热区找到，尝试从冷区获取用户
	for _, user := range v.coldUsers {
		if aead, ret, ivLen, err := v.tryDecrypt(user, bs, command); err == nil {
			v.hotUsers.Add(user.Email, user)
			return user, aead, ret, ivLen, nil
		}
	}
	return nil, nil, nil, 0, ErrNotFound
}

// _tryDecryptFromCache 尝试从LRU缓存中解密和验证用户
func (v *Validator) tryDecryptFromCache(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	for _, key := range v.hotUsers.Keys() {
		if user, ok := v.hotUsers.Peek(key); ok {
			if aead, ret, ivLen, err := v.tryDecrypt(user.(*protocol.MemoryUser), bs, command); err == nil {
				return user.(*protocol.MemoryUser), aead, ret, ivLen, nil
			}
		}
	}
	return nil, nil, nil, 0, ErrNotFound
}

// _tryDecrypt 尝试解密和验证给定的用户
func (v *Validator) tryDecrypt(user *protocol.MemoryUser, bs []byte, command protocol.RequestCommand) (aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	account := user.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() {
		// 非AEAD密码逻辑
		// ...
		return nil, nil, 0, ErrNotFound
	}

	if len(bs) < 32 {
		return nil, nil, 0, errors.New("payload too short for AEAD")
	}

	aeadCipher := account.Cipher.(*AEADCipher)
	ivLen = aeadCipher.IVSize()
	iv := bs[:ivLen]
	subkey := make([]byte, 32)
	subkey = subkey[:aeadCipher.KeyBytes]
	hkdfSHA1(account.Key, iv, subkey)         // hkdfSHA1需要被您自己的函数替换
	aead = aeadCipher.AEADAuthCreator(subkey) // AEADAuthCreator是一个示例函数名，需要替换成您的实际函数

	switch command {
	case protocol.RequestCommandTCP:
		data := make([]byte, 4+aead.NonceSize())
		ret, err = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
	case protocol.RequestCommandUDP:
		data := make([]byte, 8192)
		ret, err = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
	}

	if err != nil {
		return nil, nil, ivLen, err
	}

	err = account.CheckIV(iv) // CheckIV需要被您自己的函数替换

	return aead, ret, ivLen, err
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	if !v.behaviorFused {
		v.behaviorFused = true
		if v.behaviorSeed == 0 {
			for _, user := range v.coldUsers {
				account := user.Account.(*MemoryAccount)
				hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
				hashkdf.Write(account.Key)
				v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
			}
		}
	}
	return v.behaviorSeed
}
