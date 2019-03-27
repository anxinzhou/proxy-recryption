package proxy

/*
#cgo CFLAGS: -I ../include
#cgo LDFLAGS: -L../ -lproxy
#include "proxy.h"
 */
import "C"
import "unsafe"

const (
	G1_LEN = 128;
	G2_LEN = 128;
	GT_LEN = 128;
	ZR_LEN = 20;
)

type Cipher struct {
	Share1 []byte `json:"share1"`
	Share2 []byte `json:"share2"`
}

func init() {
	C.init()
}

func GenPrivateKey() []byte {
	delegatorPrivateKey:= make([]byte,ZR_LEN)
	C.gen_private_key((*C.uchar)(&delegatorPrivateKey[0]))
	return delegatorPrivateKey
}

func GenRecrpytionKey(delegateePublicKey []byte, delegatorPrivateKey []byte, delegatorSignKey []byte) []byte {
	recryptionKey:= make([]byte,G2_LEN)
	C.gen_recryption_key((*C.uchar)(&recryptionKey[0]),
		(*C.uchar)(&delegateePublicKey[0]),
		(*C.uchar)(&delegatorPrivateKey[0]),
		(*C.uchar)(&delegatorSignKey[0]))
	return recryptionKey
}

func DelegateePublicKeyFromPrivateKey(privateKey []byte) []byte {
	pbk:=make([]byte,G2_LEN)
	C.delegatee_publickey_from_private_key((*C.uchar)(unsafe.Pointer(&pbk[0])),
	(*C.uchar)(&privateKey[0]))
	return pbk
}

func EncFirstLevel(cipher *Cipher) {
	//TODO
}

func DecFirstLevel() {

}

func EncSecondLevel(message []byte, delegatorPrivateKey []byte, delegatorSignKey []byte) *Cipher {
	cipher:= &Cipher{
		Share1: make([]byte,G1_LEN),
		Share2: make([]byte,GT_LEN),
	}
	C.enc_second_level((*C.uchar)(&cipher.Share1[0]),
		(*C.uchar)(&cipher.Share2[0]),
		(*C.uchar)(&message[0]),
		(*C.uchar)(&delegatorPrivateKey[0]),
		(*C.uchar)(&delegatorSignKey[0]))
	return cipher
}

func DecSecondLevel() {
	//TODO
}

func EncRecryption(cipher *Cipher, recryptionKey []byte) *Cipher {
	recryptedCipher:= &Cipher{
		Share1: make([]byte,GT_LEN),
		Share2: make([]byte,GT_LEN),
	}
	C.enc_recryption((*C.uchar)(&(recryptedCipher.Share1[0])),
		(*C.uchar)(&recryptedCipher.Share2[0]),
		(*C.uchar)(&cipher.Share1[0]),
		(*C.uchar)(&cipher.Share2[0]),
		(*C.uchar)(&recryptionKey[0]))
	return recryptedCipher
}

func DecRecryption(cipher *Cipher, delegateePrivateKey []byte) []byte {
	m:=make([]byte,GT_LEN)
	C.dec_recryption((*C.uchar)(&m[0]),
		(*C.uchar)(&cipher.Share1[0]),
		(*C.uchar)(&cipher.Share2[0]),
		(*C.uchar)(&delegateePrivateKey[0]))
	return m
}