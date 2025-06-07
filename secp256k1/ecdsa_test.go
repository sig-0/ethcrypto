package secp256k1

import (
	"crypto/rand"
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
