//go:build ignore

// SPDX-License-Identifier: GPL-3.0-only
// Run from tests/interop/encryption using the pinned Xray module.
package main

import (
	"encoding/hex"
	"encoding/json"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"lukechampine.com/blake3"
	"os"
)

func main() {
	key := make([]byte, 96)
	for j := range key {
		key[j] = byte(j)
	}
	var vectors []map[string]any
	for _, length := range []int{0, 1, 31, 64, 1023, 1024, 1025, 1216, 16645} {
		context := make([]byte, length)
		for j := range context {
			context[j] = byte(j*37 + 255)
		}
		derived := make([]byte, 32)
		blake3.DeriveKey(derived, string(context), key)
		vectors = append(vectors, map[string]any{"length": length, "derived": hex.EncodeToString(derived)})
	}
	message := []byte("authenticated application payload")
	header := []byte{23, 3, 3, 0, byte(len(message) + 16)}
	var aeads []map[string]any
	for _, aes := range []bool{true, false} {
		aead := encryption.NewAEAD([]byte{0, 255, 128, 1}, key, aes)
		sealed := aead.Seal(nil, nil, message, header)
		aeads = append(aeads, map[string]any{"aes": aes, "sealed": hex.EncodeToString(sealed)})
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"kdf": vectors, "aead": aeads})
}
