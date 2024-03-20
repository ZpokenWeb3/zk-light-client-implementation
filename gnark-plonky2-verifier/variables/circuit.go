package variables

import (
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/poseidon"
)

type Proof struct {
	WiresCap                  FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	PlonkZsPartialProductsCap FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	QuotientPolysCap          FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	Openings                  OpeningSet
	OpeningProof              FriProof
}

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs []gl.Variable // Length = CommonCircuitData.NumPublicInputs
}

type VerifierOnlyCircuitData struct {
	ConstantSigmasCap FriMerkleCap
	CircuitDigest     poseidon.BN254HashOut
}
