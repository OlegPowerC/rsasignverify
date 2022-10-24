package licensebycert

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestRsaSign(t *testing.T) {
	KeyFile := "test.key"
	PemFile := "test.pem"
	TestSMess := "Test Sign Message"

	KeyF, KeyFileErr := os.Open(KeyFile)
	if KeyFileErr != nil {
		fmt.Println(KeyFileErr)
		os.Exit(1)
	}
	defer KeyF.Close()

	KeyBytes, _ := ioutil.ReadAll(KeyF)

	PemF, LicPemFileErr := os.Open(PemFile)
	if LicPemFileErr != nil {
		fmt.Println(LicPemFileErr)
		os.Exit(1)
	}
	defer PemF.Close()

	PemBytes, _ := ioutil.ReadAll(PemF)

	Signed, _ := RsaSign([]byte(TestSMess), KeyBytes)
	verify := RsaVerify([]byte(TestSMess), PemBytes, string(Signed))
	if verify != nil {
		t.Errorf("Verify error: %s", verify)
	}
}
