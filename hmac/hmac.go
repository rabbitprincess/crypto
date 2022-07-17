package hmac

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"hash"
)

type Hash struct {
	hash hash.Hash
}

func (t *Hash) InitKey(_key []byte) {
	t.hash = hmac.New(sha512.New, _key)
}

func (t *Hash) Write(_bt []byte) (n int, err error) {
	return t.hash.Write(_bt)
}

func (t *Hash) Sum() []byte {
	bt := t.hash.Sum(nil)
	return bt
}

func FromBytes(_key []byte, _content []byte) ([]byte, error) {
	var err error
	hash := Hash{}
	hash.InitKey(_key)
	_, err = hash.Write(_content)
	if err != nil {
		return nil, err
	}
	btHash := hash.Sum()
	return btHash, nil
}

func FromInterface(_key []byte, _i interface{}) ([]byte, error) {
	buf, err := json.Marshal(_i)
	if err != nil {
		return nil, err
	}
	return FromBytes(_key, buf)
}
