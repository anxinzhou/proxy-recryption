package main

import "C"
import (
	"log"
	"math/big"
	"proxy"
)

const (
	G1_LEN = 128;
	G2_LEN = 128;
	GT_LEN = 128;
	ZR_LEN = 20;
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	delegatorPrivateKey:= proxy.GenPrivateKey()
	delegatorSignKey:= proxy.GenPrivateKey()

	delegateePrivateKey:= proxy.GenPrivateKey()
	delegateePublicKey:=proxy.DelegateePublicKeyFromPrivateKey(delegateePrivateKey)

	recryptionKey:= proxy.GenRecrpytionKey(delegateePublicKey,delegatorPrivateKey,delegatorSignKey)

	mBuffer,_:= new(big.Int).SetString("3213123432423434",10)
	//m:=make([]byte,GT_LEN)
	//m[0]=2
	m:=mBuffer.Bytes()
	prefix:=make([]byte,GT_LEN-len(m))
	m=append(prefix,m...)
	log.Println(m)
	cipher:=proxy.EncSecondLevel(m, delegatorPrivateKey, delegatorSignKey)
	recryptedCipher:=proxy.EncRecryption(cipher, recryptionKey)
	recoveredM:=proxy.DecRecryption(recryptedCipher,delegateePrivateKey)
	log.Println(recoveredM)
	//reverse(recoveredM)
	log.Println("recovered message",new(big.Int).SetBytes(recoveredM))
}