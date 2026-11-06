package secp256k1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

const (
	ecrecoverDataLength = 128 // 4 * 32B (hash, v, r, s)
	signatureSize       = 65  // bytes
)

var (
	zero           = uint256.NewInt(0)
	one            = uint256.NewInt(1)
	secp256k1n     = uint256.MustFromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secp256k1nHalf = uint256.NewInt(0).Div(secp256k1n, uint256.NewInt(2))
)

var (
	ErrInvalidVValue  = errors.New("invalid v signature value")
	ErrInvalidRValue  = errors.New("invalid r signature value")
	ErrInvalidSValue  = errors.New("invalid s signature value")
	ErrInvalidSigSize = errors.New("invalid signature size")
)

// PrepareECRecover constructs the 128-byte payload expected by ECRecover.
// It constructs a payload:
//   - [0..31] bytes: the 32-byte message hash,
//   - [32..63] bytes: v (as a 32-byte big-endian integer),
//   - [64..95] bytes: r (as a 32-byte big-endian integer),
//   - [96..127] bytes: s (as a 32-byte big-endian integer).
func PrepareECRecover(messageHash []byte, v, r, s *big.Int) []byte {
	payload := make([]byte, 128)

	// Prepare the message hash
	copy(payload[0:32], messageHash)

	// Prepare the v param
	vBytes := v.FillBytes(make([]byte, 32))
	copy(payload[32:64], vBytes)

	// Prepare the r param
	rBytes := r.FillBytes(make([]byte, 32))
	copy(payload[64:96], rBytes)

	// Prepare the s param
	sBytes := s.FillBytes(make([]byte, 32))
	copy(payload[96:128], sBytes)

	return payload
}

// ECRecover decrypts the signer address using the secp256k1 curve
// recovery mechanism.
//
// The input data is expected to be 128 bytes:
//   - 0..31   => message hash
//   - 32..63  => v (padded)
//   - 64..95  => r
//   - 96..127 => s
func ECRecover(payload []byte) ([]byte, error) {
	// The input data needs to be exactly 128B long.
	// We need to pad the input stream so there is no funny business
	input := rightPadZeroBytes(payload, ecrecoverDataLength)

	messageHash := input[:32]

	vRaw := uint256.NewInt(0).SetBytes(input[32:64])
	r := uint256.NewInt(0).SetBytes(input[64:96])
	s := uint256.NewInt(0).SetBytes(input[96:128])

	// Check the V value
	vTerm, overflow := vRaw.Uint64WithOverflow()
	if overflow {
		return nil, ErrInvalidVValue
	}

	// Normalize V to {27, 28}
	vNormalized, err := NormalizeV(vTerm)
	if err != nil {
		return nil, err
	}

	// Check the R value
	if zero.Cmp(r) >= 0 || r.Cmp(secp256k1n) >= 0 {
		return nil, ErrInvalidRValue
	}

	// Check the S value
	if zero.Cmp(s) >= 0 || s.Cmp(secp256k1n) >= 0 {
		return nil, ErrInvalidSValue
	}

	// Recover the public key
	publicKey, err := secp256k1Recover(
		r.Bytes32(),
		s.Bytes32(),
		vNormalized,
		messageHash,
	)
	if err != nil {
		return nil, err
	}

	// Construct the address (the last 20B of the public key keccak)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(publicKey)

	address := hasher.Sum(nil)[12:]

	// Pad the address
	return leftPadZeroBytes(address, 32), nil
}

// NormalizeV handles legacy (pre-EIP-155), EIP-155, and typed transaction v values.
//
// Note: this function does not perform chain ID verification and matching. Make sure
// this logic is done at some point before normalizing the V value, as the process works
// with the embedded chain ID.
//
// Returns the final "recovery byte" in the range {27, 28}
func NormalizeV(vTerm uint64) (byte, error) {
	switch {
	// Typed transactions (EIP-2930 / EIP-1559):
	// v in {0, 1}
	case vTerm == 0 || vTerm == 1:
		return byte(vTerm) + 27, nil

	// Pre-EIP-155 transactions (legacy)
	// v in {27, 28}
	case vTerm == 27 || vTerm == 28:
		return byte(vTerm), nil

	// EIP-155 transactions
	// if v >= 35 then v == chainID * 2 + 35 or 36
	case vTerm >= 35:
		var (
			// chainID = floor((vTerm - 35) / 2) or floor((vTerm - 36)/2)
			// We'll compute parity to see if it's +35 or +36
			is36 = (vTerm == 36) || (vTerm > 36 && (vTerm-36)%2 == 0)
			base = vTerm - 35
		)

		if is36 {
			base = vTerm - 36
		}

		if chainID := base / 2; chainID == 0 {
			// Some transactions might still sign with v=35 or 36 and chainID=0,
			// but that's atypical.
			//
			// We treat it as invalid
			return 0, ErrInvalidVValue
		}

		// Recovery ID depends on parity (35 => v=27, 36 => v=28)
		if is36 {
			return 28, nil
		}

		return 27, nil
	}

	return 0, ErrInvalidVValue
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
	signature := make([]byte, signatureSize)

	// Set the V value as the first byte
	// (the crypto lib used expects this for recovery)
	// [v, r, s]
	signature[0] = vByte

	// Copy the R value
	copy(signature[1:33], rBytes[:])

	// Copy the S value
	copy(signature[33:65], sBytes[:])

	// Recover the actual public key
	pubKey, _, err := ecdsa.RecoverCompact(signature, messageHash)
	if err != nil {
		return nil, err
	}

	return pubKey.SerializeUncompressed()[1:], nil
}

// SignHash signs the given hash using the given private key
func SignHash(privateKey *secp256k1.PrivateKey, hash []byte) []byte {
	// Sign the hash using the private key
	sig := ecdsa.SignCompact(privateKey, hash, false)

	// Convert the signature to the Ethereum sig format
	// with v being at the end
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[64] = v

	return sig
}

// VerifySigValues verifies the V, R and S part of the Ethereum signatures.
// Values it checks against:
//   - R in range [1, secp256k1n)
//   - S in range [1, secp256k1n) OR in range [1, secp256k1nHalf] if homestead
//   - V either 0 or 1
func VerifySigValues(v byte, rBig, sBig *big.Int, homesteadActive bool) error {
	var (
		r = uint256.NewInt(0).SetBytes(rBig.Bytes())
		s = uint256.NewInt(0).SetBytes(sBig.Bytes())
	)

	// Check the R value.
	// It needs to be in range [1, secp256k1n)
	if zero.Cmp(r) >= 0 || r.Cmp(secp256k1n) >= 0 || r.Cmp(one) < 0 {
		return ErrInvalidRValue
	}

	// Check the S value.
	// It needs to be in range [1, secp256k1n)
	if zero.Cmp(s) >= 0 || s.Cmp(secp256k1n) >= 0 || s.Cmp(one) < 0 {
		return ErrInvalidSValue
	}

	// Perform the tighter check on the S param,
	// if homestead is active.
	// S needs to be in range [1, secp256k1nHalf]
	if homesteadActive && s.Cmp(secp256k1nHalf) > 0 {
		return ErrInvalidSValue
	}

	// Check the V value.
	// It needs to be either 0 or 1 (parity)
	if v != 0 && v != 1 {
		return ErrInvalidVValue
	}

	return nil
}

// RecoverSigner returns the Ethereum address (20 bytes) that created
// the signature over message. Set homestead to true for the latest hardfork rules
func RecoverSigner(msg, sig []byte, homestead bool) ([20]byte, error) {
	var zeroAddr [20]byte

	if len(sig) != signatureSize {
		return zeroAddr, ErrInvalidSigSize
	}

	// Split the 65B signature
	// R || S || V
	var (
		r    = big.NewInt(0).SetBytes(sig[0:32])
		s    = big.NewInt(0).SetBytes(sig[32:64])
		vRaw = uint64(sig[64])
	)

	// Normalize V to {27, 28}
	vNorm, err := NormalizeV(vRaw)
	if err != nil {
		return zeroAddr, fmt.Errorf("invalid V value: %w", err)
	}

	vParity := vNorm - 27 // 0 or 1

	// Make sure the signature values are valid
	if err = VerifySigValues(vParity, r, s, homestead); err != nil {
		return zeroAddr, fmt.Errorf("unable to verify VRS values: %w", err)
	}

	// Keccak the message
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(msg)
	hash := hasher.Sum(nil)

	// Prepare the ECRecover payload
	payload := PrepareECRecover(
		hash,
		new(big.Int).SetUint64(vRaw),
		r,
		s,
	)

	// Recover the signer
	raw, err := ECRecover(payload)
	if err != nil {
		return zeroAddr, fmt.Errorf("unable to recover signer: %w", err)
	}

	copy(zeroAddr[:], raw[12:]) // ECRecover pads to 32B; keep the right-most 20

	return zeroAddr, nil
}

// PubKeyToAddress derives the Ethereum address from the given public key
func PubKeyToAddress(pk *secp256k1.PublicKey) [20]byte {
	var (
		uncompressed = pk.SerializeUncompressed()
		pubBytes     = uncompressed[1:] // drop the 0x04
	)

	// Keccak the pubkey
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubBytes)
	hash := hasher.Sum(nil)

	// The address is the lower 20B of the hash
	var addr [20]byte

	copy(addr[:], hash[12:])

	return addr
}
