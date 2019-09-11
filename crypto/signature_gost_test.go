package crypto

import (
	"encoding/hex"
	"gostBlockchain/common/hexutil"
	"gostBlockchain/crypto/gost3410"
	"testing"
)

func TestPubKeyGeneration(t *testing.T) {
	key, _ := GenerateKey()
	s := "Hello, world!"
	h := Keccak256([]byte(s))
	sigRS, _ := gost3410.SignRFC7091((*gost3410.PrivateKey)(key), h)

	for i := 0; i < (gost3410.S256().H+1)*2; i++ {
		pk, err := gost3410.RecoverKeyFromSignature(gost3410.S256(), sigRS, h, i, true)
		if (err == nil) {
			if (pk.X.Cmp(key.X) == 0 && pk.Y.Cmp(key.Y) == 0) {
				return
			}
		}
	}
	t.Fail()
}

func TestSig(t *testing.T) {
	key, _ := GenerateKey()
	t.Logf("Private: %x", (*gost3410.PrivateKey)(key).Serialize())
	t.Logf("Addr: %x", PubkeyToAddress(key.PublicKey))
	//s := "Hello, world!"
	//h := Keccak256([]byte(s))
	testmsg := hexutil.MustDecode("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
	//sig, err := Sign(h, key)
	//sig2, err2 := SignOrig(h, key)

	//sigRS, _ := gost3410.SignRFC7091((*gost3410.PrivateKey)(key), h)
	//sigRS2, _ := gost3410.SignRFC6979((*gost3410.PrivateKey)(key), h)

	sig, _ := Sign(testmsg, key)

	//sig, err := Sign(h, key)
	//sig2, err2 := SignOrig(h, key)

	//sigRS, _ := gost3410.SignRFC7091((*gost3410.PrivateKey)(key), h)
	//sigRS2, _ := gost3410.SignRFC6979((*gost3410.PrivateKey)(key), h)

	t.Log("compactSig:  ", hex.EncodeToString(sig))

	t.Log("")

	pubKey, err := Ecrecover(testmsg, sig)

	ecdsaPub0, _ := gost3410.SigToPub(testmsg, sig)
	ecdsaPubC := CompressPubkey(ecdsaPub0)

	ecdsaPub, _ := UnmarshalPubkey(pubKey)

	b, err := hex.DecodeString(hex.EncodeToString(pubKey))
	//b = append([]byte{0x4}, b...)
	testPub,_ := UnmarshalPubkey(b)

	t.Log("")

	t.Log("PubKey:  ", hex.EncodeToString(pubKey))
	t.Log("PubKey Compressed:  ", hex.EncodeToString(ecdsaPubC))
	t.Log("PubKey Orig:  ", ecdsaPub)
	t.Log("PubKey Test:  ", b)
	t.Log("PubKey Test:  ", testPub)

	t.Log("")

	t.Log("Res:  ", VerifySignature(pubKey, testmsg, sig[:len(sig)-1]))
	t.Log("Error:  ", err)

	t.Log("")

	recoveredAddr := PubkeyToAddress(*ecdsaPub)
	t.Logf("%x", recoveredAddr)
}

func TestSigMulti(t *testing.T) {
	for i := 0; i < 10000; i++ {
		TestSig(t)
	}
}