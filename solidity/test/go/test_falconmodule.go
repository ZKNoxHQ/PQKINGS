package main

import (
	"fmt"

	"github.com/ZKNoxHQ/ETHFALCON/falcon"
)

func main() {
	pk, sk, err := falcon.GenerateKeypair()
	if err != nil {
		fmt.Println("❌ Keypair error:", err)
		return
	}

	msg := []byte("Hello from ZKNOX")

	sig, err := falcon.SignMessage(msg, sk)
	if err != nil {
		fmt.Println("❌ Signing error:", err)
		return
	}

	valid, err := falcon.VerifySignature(sig, msg, pk)
	if err != nil {
		fmt.Println("❌ Verification error:", err)
		return
	}

	if valid {
		fmt.Println("✅ Signature is valid!")
	} else {
		fmt.Println("❌ Signature is invalid.")
	}
}
