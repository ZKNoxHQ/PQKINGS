package falcon

/*
#cgo CFLAGS: -I${SRCDIR}/nistfalcon/src
#cgo LDFLAGS: -L${SRCDIR}/nistfalcon/build 
#cgo LDFLAGS: -lfalcon

#include <stdlib.h>
#include "api.h"

// Wrapper for crypto_sign_keypair, crypto_sign, crypto_sign_open

*/
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	PublicKeySize  = 897  // Adjust if api.h specifies differently
	SecretKeySize  = 1281 // Adjust if api.h specifies differently
	SignatureSize  = 1330 // Falcon signature size
)

// GenerateKeypair generates a public/private keypair
func GenerateKeypair() ([]byte, []byte, error) {
	var pk [PublicKeySize]C.uchar
	var sk [SecretKeySize]C.uchar

	ret := C.crypto_sign_keypair(&pk[0], &sk[0])
	if ret != 0 {
		return nil, nil, fmt.Errorf("keypair generation failed: %d", int(ret))
	}

	pkBytes := C.GoBytes(unsafe.Pointer(&pk[0]), C.int(PublicKeySize))
	skBytes := C.GoBytes(unsafe.Pointer(&sk[0]), C.int(SecretKeySize))

	return pkBytes, skBytes, nil
}

// SignMessage signs a message using the private key
func SignMessage(message []byte, sk []byte) ([]byte, error) {
	var sm [SignatureSize]C.uchar
	var smlen C.ulonglong

	ret := C.crypto_sign(&sm[0], &smlen, (*C.uchar)(unsafe.Pointer(&message[0])), C.ulonglong(len(message)), (*C.uchar)(unsafe.Pointer(&sk[0])))
	if ret != 0 {
		return nil, fmt.Errorf("signing failed: %d", int(ret))
	}

	// Convert signature to Go byte slice
	smBytes := C.GoBytes(unsafe.Pointer(&sm[0]), C.int(smlen))
	return smBytes, nil
}

// VerifySignature verifies a signature for a given message and public key
func VerifySignature(signature []byte, message []byte, pk []byte) (bool, error) {
	var m [1024]C.uchar // Buffer for the recovered message
	var mlen C.ulonglong

	ret := C.crypto_sign_open(&m[0], &mlen, (*C.uchar)(unsafe.Pointer(&signature[0])), C.ulonglong(len(signature)), (*C.uchar)(unsafe.Pointer(&pk[0])))
	if ret != 0 {
		return false, fmt.Errorf("verification failed: %d", int(ret))
	}

	// Convert recovered message back to Go byte slice
	recoveredMessage := C.GoBytes(unsafe.Pointer(&m[0]), C.int(mlen))

	// Compare the recovered message with the original message
	if string(recoveredMessage) == string(message) {
		return true, nil
	}
	return false, nil
}
