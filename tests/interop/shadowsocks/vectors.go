// SPDX-License-Identifier: GPL-3.0-only
// Deterministic test-only known answers from Go crypto and the pinned KDF.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	SS "github.com/sagernet/sing-shadowsocks"
	S22 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"io"
	"lukechampine.com/blake3"
	"os"
	"strings"
)

func vectors() error {
	names := []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
	result := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		length := 32
		if strings.Contains(name, "aes-128") {
			length = 16
		} else if strings.Contains(name, "aes-192") {
			length = 24
		}
		modern := strings.HasPrefix(name, "2022-")
		password := "fixture-passphrase"
		key := SS.Key([]byte(password), length)
		if modern {
			key = make([]byte, length)
			for i := range key {
				key[i] = byte(i)
			}
			password = base64.StdEncoding.EncodeToString(key)
		}
		salt := make([]byte, length)
		for i := range salt {
			salt[i] = byte(128 + i)
		}
		subkey := make([]byte, length)
		if modern {
			subkey = S22.SessionKey(key, salt, length)
		} else {
			if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey); err != nil {
				return err
			}
		}
		var aead cipher.AEAD
		var err error
		if strings.Contains(name, "aes-") {
			block, e := aes.NewCipher(subkey)
			if e != nil {
				return e
			}
			aead, err = cipher.NewGCM(block)
		} else if strings.HasPrefix(name, "xchacha") {
			aead, err = chacha20poly1305.NewX(subkey)
		} else {
			aead, err = chacha20poly1305.New(subkey)
		}
		if err != nil {
			return err
		}
		nonce := make([]byte, aead.NonceSize())
		payload := []byte("independent AEAD vector")
		encodedLength := aead.Seal(nil, nonce, []byte{0, byte(len(payload))}, nil)
		nonce[0] = 1
		encodedPayload := aead.Seal(nil, nonce, payload, nil)
		v := map[string]interface{}{"cipher": name, "password": password, "master": hex.EncodeToString(key), "salt": hex.EncodeToString(salt), "subkey": hex.EncodeToString(subkey), "plaintext": string(payload), "length": hex.EncodeToString(encodedLength), "payload": hex.EncodeToString(encodedPayload)}
		if modern && strings.Contains(name, "aes-") {
			server := make([]byte, length)
			for i := range server {
				server[i] = byte(64 + i)
			}
			material := append(append([]byte{}, server...), salt...)
			identityKey := make([]byte, length)
			blake3.DeriveKey(identityKey, "shadowsocks 2022 identity subkey", material)
			block, _ := aes.NewCipher(identityKey)
			hash := blake3.Sum256(key)
			identity := make([]byte, 16)
			block.Encrypt(identity, hash[:16])
			v["server_key"] = hex.EncodeToString(server)
			v["identity_header"] = hex.EncodeToString(identity)
		}
		result = append(result, v)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
