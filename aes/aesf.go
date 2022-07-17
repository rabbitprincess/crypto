package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func convKeyLen(_key []byte) ([]byte, error) {
	// bt_key 길이는 16 24 32 (128 bit / 192 bit / 256 bit ) 중 1개 이여야 함
	keyLen := len(_key)
	if keyLen > 32 {
		return nil, fmt.Errorf("key is too long")
	} else if keyLen < 8 {
		return nil, fmt.Errorf("key is too short")
	}

	var keyLenAfter int
	{
		if keyLen <= 16 {
			keyLenAfter = 16
		} else if keyLen <= 24 {
			keyLenAfter = 24
		} else if keyLen <= 32 {
			keyLenAfter = 32
		}
	}

	if keyLen > keyLenAfter {
		_key = _key[:keyLenAfter]
	} else if keyLen < keyLenAfter {
		_key = append(_key, bytes.Repeat([]byte{0}, keyLenAfter-keyLen)...)
	}
	return _key, nil
}

func Encode(_key []byte, _content []byte) ([]byte, error) {
	var err error
	_key, err = convKeyLen(_key)
	if err != nil {
		return nil, err
	}

	var lenNormal int
	var lenLastPadded int
	{
		lenNormal = 1 + len(_content)
		mod := lenNormal % aes.BlockSize
		if mod != 0 {
			lenLastPadded = aes.BlockSize - mod
		}
		lenNormal += lenLastPadded
	}

	// 암호화할 원문 작성
	var normal []byte
	{
		normal = make([]byte, lenNormal)
		normal[0] = byte(lenLastPadded)
		copy(normal[1:], _content)
	}

	// 암호화
	var crypto []byte
	{
		block, err := aes.NewCipher([]byte(_key)) // AES 대칭키 암호화 블록 생성 -
		if err != nil {
			return nil, err
		}

		crypto = make([]byte, aes.BlockSize+len(normal))        // 초기화 벡터 공간(aes.BlockSize)만큼 더 생성
		iv := crypto[:aes.BlockSize]                            // 부분 슬라이스로 초기화 벡터 공간을 가져옴
		if _, err := io.ReadFull(rand.Reader, iv); err != nil { // 랜덤 값을 초기화 벡터에 넣어줌
			return nil, err
		}

		mode := cipher.NewCBCEncrypter(block, iv)        // 암호화 블록과 초기화 벡터를 넣어서 암호화 블록 모드 인스턴스 생성
		mode.CryptBlocks(crypto[aes.BlockSize:], normal) // 암호화 블록 모드 인스턴스로
	}

	return crypto, nil
}

func Decode(_key []byte, _content []byte) ([]byte, error) {
	var err error
	_key, err = convKeyLen(_key)
	if err != nil {
		return nil, err
	}

	if len(_content)%aes.BlockSize != 0 { // 블록 크기의 배수가 아니면 리턴
		return nil, fmt.Errorf("content size is not multiple of block size")
	}
	block, err := aes.NewCipher([]byte(_key)) // AES 대칭키 암호화 블록 생성
	if err != nil {
		return nil, err
	}

	iv := _content[:aes.BlockSize]      // 부분 슬라이스로 초기화 벡터 공간을 가져옴
	_content = _content[aes.BlockSize:] // 부분 슬라이스로 암호화된 데이터를 가져옴

	content := make([]byte, len(_content))    // 평문 데이터를 저장할 공간 생성
	mode := cipher.NewCBCDecrypter(block, iv) // 암호화 블록과 초기화 벡터를 넣어서
	// 복호화 블록 모드 인스턴스 생성
	mode.CryptBlocks(content, _content) // 복호화 블록 모드 인스턴스로 복호화

	// 길이 추출하고 길이 값 만큼만 해독된 문구 리턴
	lenPad := int(content[0])
	if lenPad != 0 {
		content = content[1 : len(content)-lenPad]
	}
	return content, nil
}
