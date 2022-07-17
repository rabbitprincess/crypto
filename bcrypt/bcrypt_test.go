package bcrypt

import (
	"fmt"
	"testing"
)

func Test_bcrypt(_t *testing.T) {
	pw := []byte("test_pw")
	hash, err := Encrypt(pw)
	if err != nil {
		_t.Fatal(err)
	}

	is_valid, err := Verify(hash, pw)
	if is_valid != true {
		_t.Errorf("err")
	}

	fmt.Println(pw)
	fmt.Println(hash)
}
