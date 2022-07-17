package base58

import (
	"errors"
	"math/big"

	"github.com/gokch/crypto/sha3"
)

var (
	errWrongChecksum            = errors.New("checksum is wrong")
	errMissingVersionOrChecksum = errors.New("missing version or checksum")
)

// checksum : sha256 hash 를 두번 돌린 이후의 첫 4 byte 값
func checksum(_bt []byte) [4]byte {
	hash_1, _ := sha3.FromBytes(_bt)
	hash_2, _ := sha3.FromBytes(hash_1[:])

	var checksum [4]byte
	copy(checksum[:], hash_2[:4])
	return checksum
}

// Encode encodes a byte slice to a modified base58 string.
func Encode(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	// maximum length of output is log58(2^(8*len(b))) == len(b) * 8 / log(58)
	maxlen := int(float64(len(b))*1.365658237309761) + 1
	answer := make([]byte, 0, maxlen)
	mod := new(big.Int)
	for x.Sign() > 0 {
		// Calculating with big.Int is slow for each iteration.
		//    x, mod = x / 58, x % 58
		//
		// Instead we can try to do as much calculations on int64.
		//    x, mod = x / 58^10, x % 58^10
		//
		// Which will give us mod, which is 10 digit base58 number.
		// We'll loop that 10 times to convert to the answer.

		x.DivMod(x, bigRadix10, mod)
		if x.Sign() == 0 {
			// When x = 0, we need to ensure we don't add any extra zeros.
			m := mod.Int64()
			for m > 0 {
				answer = append(answer, alphabet[m%58])
				m /= 58
			}
		} else {
			m := mod.Int64()
			for i := 0; i < 10; i++ {
				answer = append(answer, alphabet[m%58])
				m /= 58
			}
		}
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, alphabetIdx0)
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}

// base58 address 구성요소 -> version (1 byte) + input (n byte) + checksum (4 byte)
func EncodeChecksum(_input []byte, _version byte) string {
	bt := make([]byte, 0, 1+len(_input)+4)
	bt = append(bt, _version)
	bt = append(bt, _input[:]...)
	// checksum
	ckecksum := checksum(bt)
	bt = append(bt, ckecksum[:]...)

	// base58 encode
	return Encode(bt)
}

func validate(_bt []byte) (isValid bool) {
	// 마지막 4 byte checksum 과 원본 checksum 비교
	var checksumLast4Byte, checksumOri [4]byte
	copy(checksumLast4Byte[:], _bt[len(_bt)-4:])
	checksumOri = checksum(_bt[:len(_bt)-4])

	// 두 checksum 을 비교
	if checksumOri != checksumLast4Byte {
		return false
	}
	return true
}

// Decode decodes a modified base58 string to a byte slice.
func Decode(b string) []byte {
	answer := big.NewInt(0)
	scratch := new(big.Int)

	// Calculating with big.Int is slow for each iteration.
	//    x += b58[b[i]] * j
	//    j *= 58
	//
	// Instead we can try to do as much calculations on int64.
	// We can represent a 10 digit base58 number using an int64.
	//
	// Hence we'll try to convert 10, base58 digits at a time.
	// The rough idea is to calculate `t`, such that:
	//
	//   t := b58[b[i+9]] * 58^9 ... + b58[b[i+1]] * 58^1 + b58[b[i]] * 58^0
	//   x *= 58^10
	//   x += t
	//
	// Of course, in addition, we'll need to handle boundary condition when `b` is not multiple of 58^10.
	// In that case we'll use the bigRadix[n] lookup for the appropriate power.
	for t := b; len(t) > 0; {
		n := len(t)
		if n > 10 {
			n = 10
		}

		total := uint64(0)
		for _, v := range t[:n] {
			tmp := b58[v]
			if tmp == 255 {
				return []byte("")
			}
			total = total*58 + uint64(tmp)
		}

		answer.Mul(answer, bigRadix[n])
		scratch.SetUint64(total)
		answer.Add(answer, scratch)

		t = t[n:]
	}

	tmpval := answer.Bytes()

	var numZeros int
	for numZeros = 0; numZeros < len(b); numZeros++ {
		if b[numZeros] != alphabetIdx0 {
			break
		}
	}
	flen := numZeros + len(tmpval)
	val := make([]byte, flen)
	copy(val[numZeros:], tmpval)

	return val
}

func DecodeValidate(_base58 string) (isValid bool, ori []byte, version byte, err error) {
	// base58 decode
	bt := Decode(_base58)
	if len(bt) < 5 {
		return false, nil, 0, errMissingVersionOrChecksum
	}

	// validate checksum
	isValid = validate(bt)
	if isValid != true {
		return false, nil, 0, nil
	}

	version = bt[0]
	ori = bt[1 : len(bt)-4]
	return true, ori, version, nil
}
