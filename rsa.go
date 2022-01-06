package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

const _privKey string = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCaENV6+7hVMpADLhpWhvih1s2irUeSeTiZDb7VLRJVTAswyjO1
LBpmbYTaQ0RRIPDC/ztfApX85Mgi1xuNCgE2x1zDGPDJZFhSMksEwf1QEhI0B/Ml
9tq6iTFM2h5mqPo/i7Ni3HyuzpIoOsm7iR6JPxDARE3ZMqJ0HXncCrsoiwIDAQAB
AoGAWO56rED9SIClTJCiN2w1vQXHMa4gcFZ06zRaAafAu2fn1cQCUQQiQRna5DqM
BuCi2YyG8vMFLTPKqwHML3+k7tqM7KNla9LqH2WILOW4ww6R+MNu9NO7m88s1+pF
Nl0vjJAfl5dtQKZVqbydp8tVWSGQR6t6qidzq2NwjJy3WLECQQDMGSZL+LweBZ3E
WkxkqGn9uer1wSbgFgB1CEtM3CUSxUpOc3CH6JyFgCsTdYFPu3qKg5J47z4pLMH2
WRt+T66XAkEAwT6OYnDLx8BUeV2400/U6LeSKPK/zFc875mMorPz9xlZjqTD2NDQ
AtbKJ54KVVdHjnFs5IOOefUdcdnRojlILQJAbcohlcCJwUSYJ6XDbmpCCeDXCbgL
Z4OuX0ZE62WI8935KNZkdFemyxG1GlSdaPya4KQCSNe5goC3HgO1DG9kpQJAE6oW
+SN7SSdkMTl9TluIUeokQHB7XgLem48nhYMEZ3e36lEP8OdG05Mh3Sgy6v5HtNIL
/7D3daegyG4e7AAiPQJAfnffZYCxcshhdTjxYYjy4NPyijuU84kGdFUZS5LF7zYd
Qqm0RBw6gC4dnEiFi2mCGuZbF1KOqiZ2L9TxFsHsmw==
-----END RSA PRIVATE KEY-----`

func ReadPrivKeyFile(path string) (*rsa.PrivateKey, error) {
	var fileBytes []byte
	var err error
	if len(path) <= 0 {
		fileBytes = []byte(_privKey)
	} else {
		fileBytes, err = ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	block, _ := pem.Decode([]byte(fileBytes))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

// Decrypt RSA
func Decrypt(ciphertext []byte, keyPath string) ([]byte, error) {
	privKey, err := ReadPrivKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	plaintext, err := rsa.DecryptPKCS1v15( // 암호화된 데이터를 개인 키로 복호화
		rand.Reader, privKey, ciphertext,
	)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
