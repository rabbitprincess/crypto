package sha3

import (
	"encoding/json"
	"hash"

	"golang.org/x/crypto/sha3"
)

type Hash struct {
	hash hash.Hash
}

func (t *Hash) Init() {
	t.hash = sha3.New256()
}

func (t *Hash) Write(_bt []byte) (n int, err error) {
	return t.hash.Write(_bt)
}

func (t *Hash) Sum() []byte {
	bt_hash := t.hash.Sum(nil)
	return bt_hash
}

func FromBytes(_args ...[]byte) ([]byte, error) {
	var err error
	sha256 := sha3.New256()
	for i := 0; i < len(_args); i++ {
		_, err = sha256.Write(_args[i])
		if err != nil {
			return nil, err
		}
	}
	btHash := sha256.Sum(nil)
	return btHash, nil
}

func FromInterface(_i interface{}) ([]byte, error) {
	btBuf, err := json.Marshal(_i)
	if err != nil {
		return nil, err
	}
	return FromBytes(btBuf)
}
