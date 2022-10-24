package licensebycert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

func Base64Enc(b1 []byte) string {
	s1 := base64.StdEncoding.EncodeToString(b1)
	s2 := ""
	var LEN int = 76
	for len(s1) > 76 {
		s2 = s2 + s1[:LEN] + "\n"
		s1 = s1[LEN:]
	}
	s2 = s2 + s1
	return s2
}

func Base64Dec(s1 string) ([]byte, error) {
	s1 = strings.Replace(s1, "\n", "", -1)
	s1 = strings.Replace(s1, "\r", "", -1)
	s1 = strings.Replace(s1, " ", "", -1)
	return base64.StdEncoding.DecodeString(s1)
}

func RsaVerify(origData []byte, key []byte, Sign string) error {
	block, _ := pem.Decode(key)
	if block == nil {
		return errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub := pubInterface.(*rsa.PublicKey)

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := origData
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	err = rsa.VerifyPSS(pub, newhash, hashed, []byte(Sign), &opts)
	return err
}

func RsaSign(origData []byte, key []byte) ([]byte, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := origData
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	Sign, err := rsa.SignPSS(rand.Reader, priv, newhash, hashed, &opts)
	return Sign, err
}
