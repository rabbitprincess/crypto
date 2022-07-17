package bcrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// 길이 제한
// 비밀번호가 72 바이트 초과일 경우 73 bt 이후가 달라도 같다고 판정하기 때문
const (
	DEF_maxLen = 72
)

func Encrypt(_pw []byte) ([]byte, error) {
	if len(_pw) > DEF_maxLen {
		return nil, fmt.Errorf("pw len exceed | pw len must be less than %v", DEF_maxLen)
	}
	hash, err := bcrypt.GenerateFromPassword(_pw, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func Verify(_hash, _pw []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(_hash, _pw)
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, err
		}
		return false, err
	}
	return true, nil
}
