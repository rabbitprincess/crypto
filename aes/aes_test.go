package aes_test

import (
	"bytes"
	"testing"

	"github.com/gokch/crypto/aes"
)

var (
	DEF_sample__key__under_1 = []byte("")
	DEF_sample__key__1       = []byte("Q")
	DEF_sample__key__12      = []byte("QWERqwer1234")
	DEF_sample__key__16      = []byte("QWERqwer1234!@#$")
	DEF_sample__key__20      = []byte("QWERqwer1234!@#$QWER")
	DEF_sample__key__24      = []byte("QWERqwer1234!@#$QWERqwer")
	DEF_sample__key__28      = []byte("QWERqwer1234!@#$QWERqwer1234")
	DEF_sample__key__32      = []byte("QWERqwer1234!@#$QWERqwer1234!@#$")
	DEF_sample__key__over_32 = []byte("QWERqwer1234!@#$QWERqwer1234!@#$Q")

	DEF_sample__msg = []byte("QWER qwer 1234 !@#$") // only ascii
)

func Test__encode(_t *testing.T) {
	fn_test := func(_bt_key []byte, _bt_msg []byte, _is_err_expect bool) {
		bt_msg__encrypt, err := aes.Encode(_bt_key, _bt_msg)
		if err != nil {
			if _is_err_expect == true {
				return
			}
			_t.Fatal(err)
		}
		bt_msg__decrypt, err := aes.Decode(_bt_key, bt_msg__encrypt)
		if err != nil {
			if _is_err_expect == true {
				return
			}
			_t.Fatal(err)
		}
		if bytes.Compare(_bt_msg, bt_msg__decrypt) != 0 {
			_t.Errorf("not same")
		}
	}

	fn_test(DEF_sample__key__under_1, DEF_sample__msg, true)
	fn_test(DEF_sample__key__1, DEF_sample__msg, false)
	fn_test(DEF_sample__key__12, DEF_sample__msg, false)
	fn_test(DEF_sample__key__16, DEF_sample__msg, false)
	fn_test(DEF_sample__key__20, DEF_sample__msg, false)
	fn_test(DEF_sample__key__24, DEF_sample__msg, false)
	fn_test(DEF_sample__key__28, DEF_sample__msg, false)
	fn_test(DEF_sample__key__32, DEF_sample__msg, false)
	fn_test(DEF_sample__key__over_32, DEF_sample__msg, true)

}

func Test_aes256__decode(_t *testing.T) {
	fn_test := func(_bt_key, _bt_msg []byte, _bt_msg__encrypt__expect []byte) {
		bt_msg__decrypt, err := aes.Decode(_bt_key, _bt_msg__encrypt__expect)
		if err != nil {
			_t.Fatal(err)
		}
		if bytes.Compare(_bt_msg, bt_msg__decrypt) != 0 {
			_t.Errorf("not same msg | expect : %v | result : %v", _bt_msg, bt_msg__decrypt)
		}
	}

	fn_test(
		DEF_sample__key__1,
		DEF_sample__msg,
		[]byte{56, 103, 57, 92, 174, 78, 109, 213, 204, 52, 132, 176, 233, 56, 197, 29, 131, 99, 241, 82, 126, 100, 236, 13, 136, 151, 219, 8, 113, 34, 20, 227, 77, 113, 159, 176, 29, 12, 168, 113, 69, 216, 222, 121, 196, 148, 178, 214},
	)
	fn_test(
		DEF_sample__key__12,
		DEF_sample__msg,
		[]byte{218, 48, 14, 102, 215, 122, 160, 70, 246, 74, 53, 245, 117, 135, 190, 191, 161, 236, 114, 155, 116, 247, 133, 113, 89, 190, 211, 57, 146, 126, 95, 209, 14, 91, 175, 50, 38, 170, 139, 145, 231, 215, 161, 109, 179, 238, 14, 192},
	)
	fn_test(
		DEF_sample__key__16,
		DEF_sample__msg,
		[]byte{182, 158, 55, 255, 229, 91, 183, 199, 90, 208, 238, 135, 149, 222, 22, 158, 144, 85, 192, 54, 90, 160, 170, 155, 43, 53, 248, 145, 173, 29, 103, 171, 34, 60, 213, 131, 84, 46, 229, 173, 132, 240, 23, 69, 168, 90, 141, 143},
	)
	fn_test(
		DEF_sample__key__20,
		DEF_sample__msg,
		[]byte{242, 219, 183, 166, 32, 183, 145, 27, 57, 26, 30, 160, 134, 63, 241, 140, 183, 236, 253, 103, 105, 164, 1, 220, 28, 247, 178, 146, 85, 101, 86, 185, 235, 197, 214, 83, 151, 203, 8, 58, 216, 215, 200, 86, 18, 115, 54, 58},
	)
	fn_test(
		DEF_sample__key__24,
		DEF_sample__msg,
		[]byte{109, 244, 120, 224, 214, 242, 42, 131, 239, 165, 93, 165, 231, 198, 118, 206, 111, 81, 114, 39, 231, 5, 240, 179, 18, 211, 220, 163, 193, 252, 196, 174, 51, 223, 91, 221, 205, 164, 196, 171, 176, 163, 183, 233, 158, 153, 98, 35},
	)
	fn_test(
		DEF_sample__key__28,
		DEF_sample__msg,
		[]byte{203, 218, 34, 182, 120, 237, 137, 10, 228, 24, 158, 88, 249, 164, 197, 60, 243, 64, 16, 175, 16, 132, 205, 132, 39, 216, 56, 240, 211, 218, 101, 77, 230, 47, 175, 129, 63, 227, 76, 192, 113, 119, 53, 2, 114, 131, 39, 191},
	)
	fn_test(
		DEF_sample__key__32,
		DEF_sample__msg,
		[]byte{106, 186, 89, 41, 65, 198, 230, 58, 47, 236, 195, 225, 8, 239, 154, 222, 219, 204, 248, 181, 158, 239, 31, 96, 19, 63, 223, 53, 187, 222, 201, 1, 107, 40, 183, 118, 81, 39, 245, 56, 145, 91, 73, 119, 58, 68, 205, 53},
	)

	// js 에서 받은 값

}
