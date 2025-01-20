package secp256k1

// rightPadZeroBytes returns a new right padded array of the specified size,
// with the original contents of the buffer
func rightPadZeroBytes(buffer []byte, size uint64) []byte {
	if uint64(len(buffer)) >= size {
		// Nothing to pad
		return buffer
	}

	padding := make([]byte, size)
	copy(padding, buffer)

	return padding
}

// leftPadZeroBytes returns a new left padded array of the specified size,
// with the original contents of the buffer
func leftPadZeroBytes(buffer []byte, size uint64) []byte {
	bufferSize := uint64(len(buffer))

	if bufferSize >= size {
		// Nothing to pad
		return buffer
	}

	padding := make([]byte, size)
	copy(padding[size-bufferSize:], buffer)

	return padding
}
