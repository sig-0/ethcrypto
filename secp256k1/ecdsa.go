package secp256k1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/holiman/uint256"
	"github.com/sig-0/ethrlp"
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

// Magic number values required for V sig param verification
var (
	big35 = big.NewInt(35)
	big2  = big.NewInt(2)
	big0  = big.NewInt(0)
)

// ComputeLegacyTxHash parses the raw RLP bytes of a legacy transaction,
// then constructs the signature data payload, and finally calculates the keccak256 hash.
//
//   - If V >= 35 and (V - 35) / 2 > 0, we assume EIP-155 style and include
//     [chainId, 0, 0] in the RLP before hashing.
//
//   - Otherwise, we assume truly old-style (pre-EIP-155) with V in {27,28}
func ComputeLegacyTxHash(txData []byte) ([]byte, error) {
	type legacyTx struct {
		nonce    uint64
		gasPrice *big.Int
		gas      uint64
		to       *[]byte // nil is contract deployment
		value    *big.Int
		data     []byte
		v, r, s  *big.Int
	}

	var (
		emptyHash [32]byte
		tx        legacyTx
	)

	// TODO add nil RLP value checks for most fields

	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(txData)
	if err != nil {
		return emptyHash[:], fmt.Errorf("failed to decode transaction RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return emptyHash[:], fmt.Errorf("invalid transaction RLP encoding type: %s", list.GetType())
	}

	// Extract the list RLP values.
	//
	// - Pre-EIP-155 (Homestead) RLP: [nonce, gasPrice, gas, to, value, data, v, r, s]
	//
	// - EIP-155 RLP: [nonce, gasPrice, gas, to, value, data, chainId, 0, 0]
	listValues, _ := list.GetValue().([]ethrlp.Value)
	if len(listValues) != 9 {
		return emptyHash[:], fmt.Errorf(
			"invalid legacy transaction RLP encoding length: %d, expected %d",
			len(listValues),
			9,
		)
	}

	// Decode the nonce
	if listValues[0].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for nonce, %s",
			listValues[0].GetType(),
		)
	}

	nonceRaw, _ := listValues[0].GetValue().([]byte)
	tx.nonce = big.NewInt(0).SetBytes(nonceRaw).Uint64()

	// Decode the gas price
	if listValues[1].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for gas price, %s",
			listValues[1].GetType(),
		)
	}
	gasPriceRaw, _ := listValues[1].GetValue().([]byte)
	tx.gasPrice = big.NewInt(0).SetBytes(gasPriceRaw)

	// Decode the gas limit
	if listValues[2].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for gas limit, %s",
			listValues[2].GetType(),
		)
	}

	gasLimitRaw, _ := listValues[2].GetValue().([]byte)
	tx.gas = big.NewInt(0).SetBytes(gasLimitRaw).Uint64()

	// Decode the recipient address
	if listValues[3].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for to address, %s",
			listValues[3].GetType(),
		)
	}

	if toRaw := listValues[3].GetValue(); toRaw != nil {
		to, _ := toRaw.([]byte)
		tx.to = &to
	}

	// Decode the value
	if listValues[4].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for value, %s",
			listValues[4].GetType(),
		)
	}

	valueRaw, _ := listValues[4].GetValue().([]byte)
	tx.value = big.NewInt(0).SetBytes(valueRaw)

	// Decode the data
	if listValues[5].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for data, %s",
			listValues[5].GetType(),
		)
	}

	tx.data, _ = listValues[5].GetValue().([]byte)

	// Decode the v sig param
	if listValues[6].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for v sig param, %s",
			listValues[6].GetType(),
		)
	}

	vRaw, _ := listValues[6].GetValue().([]byte)
	tx.v = big.NewInt(0).SetBytes(vRaw)

	// Decode the r sig param
	if listValues[7].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[7].GetType(),
		)
	}

	rRaw, _ := listValues[7].GetValue().([]byte)
	tx.r = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[8].GetType() != ethrlp.Bytes {
		return emptyHash[:], fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[8].GetType(),
		)
	}

	sRaw, _ := listValues[8].GetValue().([]byte)
	tx.s = big.NewInt(0).SetBytes(sRaw)

	// Check for EIP-155 (V >= 35).
	// If so, chainID = (V - 35) / 2 or (V - 36) / 2
	// (we just do int arithmetic to see if chainID > 0)
	chainID := big.NewInt(0).Sub(tx.v, big35)
	chainID.Div(chainID, big2) // floor((V-35)/2)

	var rlpPayload [][]byte

	toAddressEncoding := ethrlp.EncodeBytes([]byte{})

	if tx.to != nil {
		toAddressEncoding = ethrlp.EncodeBytes(*tx.to)
	}

	// Check how the signing data should be constructed
	if tx.v.Cmp(big35) >= 0 && chainID.Sign() > 0 {
		// EIP-155 path
		// We need to RLP 9 elements
		rlpPayload = [][]byte{
			ethrlp.EncodeUint(tx.nonce),
			ethrlp.EncodeBigInt(tx.gasPrice),
			ethrlp.EncodeUint(tx.gas),
			ethrlp.EncodeBytes(toAddressEncoding),
			ethrlp.EncodeBigInt(tx.value),
			ethrlp.EncodeBytes(tx.data),
			ethrlp.EncodeBigInt(chainID),
			ethrlp.EncodeBigInt(big0),
			ethrlp.EncodeBigInt(big0),
		}
	} else {
		// Legacy, pre-EIP-155 path
		// We need to RLP 6 elements
		rlpPayload = [][]byte{
			ethrlp.EncodeUint(tx.nonce),
			ethrlp.EncodeBigInt(tx.gasPrice),
			ethrlp.EncodeUint(tx.gas),
			ethrlp.EncodeBytes(toAddressEncoding),
			ethrlp.EncodeBigInt(tx.value),
			ethrlp.EncodeBytes(tx.data),
		}
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Keccak the RLP encoding
	return keccakData(rlpEncoding), nil
}

func ComputeTypedTxHash(txData []byte) ([]byte, error) {
	var emptyHash [32]byte

	return emptyHash
}
