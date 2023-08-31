package ethcrypto

import (
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/holiman/uint256"
)

const (
	ecrecoverDataLength = 128 // 4 * 32B (hash, v, r, s)
)

var (
	zero       = uint256.NewInt(0)
	secp256k1n = uint256.MustFromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
)

var (
	ErrInvalidVValue = errors.New("invalid v signature value")
	ErrInvalidRValue = errors.New("invalid r signature value")
	ErrInvalidSValue = errors.New("invalid s signature value")
)

// ECRecover decrypts the address using the secp256k1 curve
// recovery mechanism and writes the address to the output
func ECRecover(data []byte) ([]byte, error) {
	// The input data needs to be exactly 128B long.
	// We need to pad the input stream so there is no funny business
	input := rightPadZeroBytes(data, ecrecoverDataLength)

	messageHash := input[:32]

	v := uint256.NewInt(0).SetBytes(input[32:64])
	r := uint256.NewInt(0).SetBytes(input[64:96])
	s := uint256.NewInt(0).SetBytes(input[96:128])

	// Check the V value
	vTerm, overflow := v.Uint64WithOverflow()
	if overflow {
		return nil, ErrInvalidVValue
	}

	if vTerm != 27 && vTerm != 28 {
		return nil, ErrInvalidVValue
	}

	// Check the R value
	if zero.Cmp(r) >= 0 || r.Cmp(secp256k1n) >= 0 {
		return nil, ErrInvalidRValue
	}

	// Check the S value
	if zero.Cmp(s) >= 0 || s.Cmp(secp256k1n) >= 0 {
		return nil, ErrInvalidSValue
	}

	// Calculate the v term
	vTerm -= 27

	// Recover the public key
	publicKey, err := secp256k1Recover(
		r.Bytes32(),
		s.Bytes32(),
		byte(vTerm),
		messageHash,
	)
	if err != nil {
		return nil, err
	}

	// Construct the address
	address := keccakData(publicKey)[12:]

	// Pad the address
	return leftPadZeroBytes(address, 32), nil
}

// secp256k1Recover recovers the uncompressed
// public key from a given signature
func secp256k1Recover(
	rBytes [32]byte,
	sBytes [32]byte,
	vByte byte,
	messageHash []byte,
) ([]byte, error) {
	// The signature is always 65B long
	signature := make([]byte, 65)

	// Copy the R value
	copy(signature[0:32], rBytes[:])

	// Copy the S value
	copy(signature[32:64], sBytes[:])

	// Set the V value
	signature[64] = vByte

	// Recover the actual public key
	pubKey, _, err := ecdsa.RecoverCompact(signature, messageHash)
	if err != nil {
		return nil, err
	}

	return pubKey.SerializeUncompressed()[1:], nil
}

// SignHash signs the given hash using the given private key
func SignHash(privateKey *secp256k1.PrivateKey, hash [32]byte) []byte {
	// Sing the
	sig := ecdsa.SignCompact(privateKey, hash[:], false)
	privateKey.Zero()

	// Convert the signature to the Ethereum sig format
	// with v being at the end
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[64] = v

	return sig
}
