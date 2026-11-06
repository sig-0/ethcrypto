package bn256

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLatticeReduceCurve(t *testing.T) {
	k, err := rand.Int(rand.Reader, Order)
	require.NoError(t, err)

	ks := curveLattice.decompose(k)

	if ks[0].BitLen() > 130 || ks[1].BitLen() > 130 {
		t.Fatal("reduction too large")
	} else if ks[0].Sign() < 0 || ks[1].Sign() < 0 {
		t.Fatal("reduction must be positive")
	}
}

func TestLatticeReduceTarget(t *testing.T) {
	k, err := rand.Int(rand.Reader, Order)
	require.NoError(t, err)

	ks := targetLattice.decompose(k)

	if ks[0].BitLen() > 66 || ks[1].BitLen() > 66 || ks[2].BitLen() > 66 || ks[3].BitLen() > 66 {
		t.Fatal("reduction too large")
	} else if ks[0].Sign() < 0 || ks[1].Sign() < 0 || ks[2].Sign() < 0 || ks[3].Sign() < 0 {
		t.Fatal("reduction must be positive")
	}
}
