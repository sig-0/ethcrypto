package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestECDSA_RecoverSigner(t *testing.T) {
	t.Parallel()

	k256 := func(data []byte) []byte {
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(data)

		return hasher.Sum(nil)
	}

	pubKeyToAddr := func(pk *secp256k1.PublicKey) [20]byte {
		var addr [20]byte

		uncompressed := pk.SerializeUncompressed()

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(uncompressed[1:])

		copy(addr[:], hasher.Sum(nil)[12:])

		return addr
	}

	t.Run("valid address recovery", func(t *testing.T) {
		t.Parallel()

		priv, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)

		msg := make([]byte, 32)

		_, err = rand.Read(msg)
		require.NoError(t, err)

		// Sign the message
		signature := SignHash(priv, k256(msg))

		recoveredAddr, err := RecoverSigner(msg, signature, true)
		require.NoError(t, err)

		// Make sure the address matches
		assert.Equal(t, pubKeyToAddr(priv.PubKey()), recoveredAddr)
	})
}

func TestECDSA_PubKeyToAddress(t *testing.T) {
	t.Parallel()

	stringToAddress := func(addr string) [20]byte {
		b, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
		require.NoError(t, err)

		var address [20]byte

		copy(address[:], b)

		return address
	}

	pubkeyFromHex := func(privHex string) *secp256k1.PublicKey {
		d, err := hex.DecodeString(privHex)
		require.NoError(t, err)

		return secp256k1.PrivKeyFromBytes(d).PubKey()
	}

	testTable := []struct {
		name            string
		privKey         string
		expectedAddress [20]byte
	}{
		{
			"0x4c9EfA80F5AE903E1be5A5FD36747F52Af82BbaB",
			"4c0883a69102937d6231471b5dbb6204fe512961708279ea7a1276c0e5be223e",
			stringToAddress("0x4c9EfA80F5AE903E1be5A5FD36747F52Af82BbaB"),
		},
		{
			"0xFCAd0B19bB29D4674531d6f115237E16AfCE377c",
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			stringToAddress("0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"),
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Parse the key
			pubKey := pubkeyFromHex(testCase.privKey)

			// Derive the address
			address := PubKeyToAddress(pubKey)

			assert.Equal(t, testCase.expectedAddress, address)
		})
	}
}
