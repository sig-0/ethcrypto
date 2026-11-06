package bn256

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestG1Marshal(t *testing.T) {
	_, Ga, err := RandomG1(rand.Reader)
	require.NoError(t, err)

	ma := Ga.Marshal()
	Gb := new(G1)

	_, err = Gb.Unmarshal(ma)
	require.NoError(t, err)

	mb := Gb.Marshal()

	assert.Equal(t, ma, mb)
}

func TestG2Marshal(t *testing.T) {
	_, Ga, err := RandomG2(rand.Reader)
	require.NoError(t, err)

	ma := Ga.Marshal()
	Gb := new(G2)

	_, err = Gb.Unmarshal(ma)
	require.NoError(t, err)

	mb := Gb.Marshal()

	assert.Equal(t, ma, mb)
}

func TestBilinearity(t *testing.T) {
	for i := 0; i < 2; i++ {
		a, p1, err := RandomG1(rand.Reader)
		require.NoError(t, err)

		b, p2, err := RandomG2(rand.Reader)
		require.NoError(t, err)

		e1 := Pair(p1, p2)

		e2 := Pair(&G1{curveGen}, &G2{twistGen})
		e2.ScalarMult(e2, a)
		e2.ScalarMult(e2, b)

		if *e1.p != *e2.p {
			t.Fatalf("bad pairing result: %s", e1)
		}
	}
}

func TestTripartiteDiffieHellman(t *testing.T) {
	a, err := rand.Int(rand.Reader, Order)
	require.NoError(t, err)

	b, err := rand.Int(rand.Reader, Order)
	require.NoError(t, err)

	c, err := rand.Int(rand.Reader, Order)
	require.NoError(t, err)

	pa, pb, pc := new(G1), new(G1), new(G1)
	qa, qb, qc := new(G2), new(G2), new(G2)

	_, err = pa.Unmarshal(new(G1).ScalarBaseMult(a).Marshal())
	require.NoError(t, err)

	_, err = qa.Unmarshal(new(G2).ScalarBaseMult(a).Marshal())
	require.NoError(t, err)

	_, err = pb.Unmarshal(new(G1).ScalarBaseMult(b).Marshal())
	require.NoError(t, err)

	_, err = qb.Unmarshal(new(G2).ScalarBaseMult(b).Marshal())
	require.NoError(t, err)

	_, err = pc.Unmarshal(new(G1).ScalarBaseMult(c).Marshal())
	require.NoError(t, err)

	_, err = qc.Unmarshal(new(G2).ScalarBaseMult(c).Marshal())
	require.NoError(t, err)

	k1 := Pair(pb, qc)
	k1.ScalarMult(k1, a)
	k1Bytes := k1.Marshal()

	k2 := Pair(pc, qa)
	k2.ScalarMult(k2, b)
	k2Bytes := k2.Marshal()

	k3 := Pair(pa, qb)
	k3.ScalarMult(k3, c)
	k3Bytes := k3.Marshal()

	if !bytes.Equal(k1Bytes, k2Bytes) || !bytes.Equal(k2Bytes, k3Bytes) {
		t.Errorf("keys didn't agree")
	}
}

func TestG2SelfAddition(t *testing.T) {
	s, err := rand.Int(rand.Reader, Order)
	require.NoError(t, err)

	p := new(G2).ScalarBaseMult(s)

	if !p.p.IsOnCurve() {
		t.Fatal("p isn't on curve")
	}

	m := p.Add(p, p).Marshal()
	if _, err := p.Unmarshal(m); err != nil {
		t.Fatalf("p.Add(p, p) ∉ G₂: %v", err)
	}
}

func TestRandomG2Marshal(t *testing.T) {
	for i := 0; i < 10; i++ {
		n, g2, err := RandomG2(rand.Reader)
		if err != nil {
			t.Error(err)

			continue
		}

		t.Logf("%v: %x\n", n, g2.Marshal())
	}
}

func TestPairings(t *testing.T) {
	a1 := new(G1).ScalarBaseMult(bigFromBase10("1"))
	a2 := new(G1).ScalarBaseMult(bigFromBase10("2"))
	a37 := new(G1).ScalarBaseMult(bigFromBase10("37"))
	an1 := new(G1).ScalarBaseMult(
		bigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495616"),
	)

	b0 := new(G2).ScalarBaseMult(bigFromBase10("0"))
	b1 := new(G2).ScalarBaseMult(bigFromBase10("1"))
	b2 := new(G2).ScalarBaseMult(bigFromBase10("2"))
	b27 := new(G2).ScalarBaseMult(bigFromBase10("27"))
	b999 := new(G2).ScalarBaseMult(bigFromBase10("999"))
	bn1 := new(G2).ScalarBaseMult(
		bigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495616"),
	)

	p1 := Pair(a1, b1)
	pn1 := Pair(a1, bn1)
	np1 := Pair(an1, b1)

	if pn1.String() != np1.String() {
		t.Error("Pairing mismatch: e(a, -b) != e(-a, b)")
	}

	if !PairingCheck([]*G1{a1, an1}, []*G2{b1, b1}) {
		t.Error("MultiAte check gave false negative!")
	}

	p0 := new(GT).Add(p1, pn1)
	p0_2 := Pair(a1, b0)

	if p0.String() != p0_2.String() {
		t.Error("Pairing mismatch: e(a, b) * e(a, -b) != 1")
	}

	p0_3 := new(GT).ScalarMult(
		p1,
		bigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
	)
	if p0.String() != p0_3.String() {
		t.Error("Pairing mismatch: e(a, b) has wrong order")
	}

	p2 := Pair(a2, b1)
	p2_2 := Pair(a1, b2)
	p2_3 := new(GT).ScalarMult(p1, bigFromBase10("2"))

	if p2.String() != p2_2.String() {
		t.Error("Pairing mismatch: e(a, b * 2) != e(a * 2, b)")
	}

	if p2.String() != p2_3.String() {
		t.Error("Pairing mismatch: e(a, b * 2) != e(a, b) ** 2")
	}

	if p2.String() == p1.String() {
		t.Error("Pairing is degenerate!")
	}

	if PairingCheck([]*G1{a1, a1}, []*G2{b1, b1}) {
		t.Error("MultiAte check gave false positive!")
	}

	p999 := Pair(a37, b27)
	p999_2 := Pair(a1, b999)

	if p999.String() != p999_2.String() {
		t.Error("Pairing mismatch: e(a * 37, b * 27) != e(a, b * 999)")
	}
}

func BenchmarkG1(b *testing.B) {
	x, err := rand.Int(rand.Reader, Order)
	require.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		new(G1).ScalarBaseMult(x)
	}
}

func BenchmarkG2(b *testing.B) {
	x, err := rand.Int(rand.Reader, Order)
	require.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		new(G2).ScalarBaseMult(x)
	}
}

func BenchmarkPairing(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Pair(&G1{curveGen}, &G2{twistGen})
	}
}
