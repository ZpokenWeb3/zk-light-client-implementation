package tests

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/wormhole-foundation/example-near-light-client/challenger"
	"github.com/wormhole-foundation/example-near-light-client/fri"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/poseidon"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"testing"
)

type TestFriCircuit struct {
	ProofWithPis            variables.ProofWithPublicInputs
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData
	CommonCircuitData       types.CommonCircuitData
}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	commonCircuitData := circuit.CommonCircuitData
	verifierOnlyCircuitData := circuit.VerifierOnlyCircuitData
	proofWithPis := circuit.ProofWithPis

	glApi := gl.New(api)
	poseidonChip := poseidon.NewGoldilocksChip(api)
	friChip := fri.NewChip(api, &commonCircuitData, &commonCircuitData.FriParams)
	challengerChip := challenger.NewChip(api)

	challengerChip.ObserveBN254Hash(verifierOnlyCircuitData.CircuitDigest)
	challengerChip.ObserveHash(poseidonChip.HashNoPad(proofWithPis.PublicInputs))
	challengerChip.ObserveCap(proofWithPis.Proof.WiresCap)
	plonkBetas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges)
	glApi.AssertIsEqual(plonkBetas[0], gl.NewVariable("13723612720980423225"))
	plonkGammas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges)
	glApi.AssertIsEqual(plonkGammas[0], gl.NewVariable("16968338265917648087"))
	challengerChip.ObserveCap(proofWithPis.Proof.PlonkZsPartialProductsCap)
	plonkAlphas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk alphas
	glApi.AssertIsEqual(plonkAlphas[0], gl.NewVariable("12762198930091358918"))

	challengerChip.ObserveCap(proofWithPis.Proof.QuotientPolysCap)
	plonkZeta := challengerChip.GetExtensionChallenge()
	glApi.AssertIsEqual(plonkZeta[0], gl.NewVariable("6945010638292076810"))

	challengerChip.ObserveOpenings(friChip.ToOpenings(proofWithPis.Proof.Openings))

	friChallenges := challengerChip.GetFriChallenges(
		proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
		proofWithPis.Proof.OpeningProof.FinalPoly,
		proofWithPis.Proof.OpeningProof.PowWitness,
		commonCircuitData.Config.FriConfig,
	)

	api.AssertIsEqual(friChallenges.FriAlpha[0].Limb, 1105999839490505715)

	api.AssertIsEqual(friChallenges.FriBetas[0][0].Limb, uint64(14109475646207874975))

	api.AssertIsEqual(friChallenges.FriPowResponse.Limb, 57752885224107)
	//
	x := uint64(6306766726523865547)
	api.AssertIsEqual(friChallenges.FriQueryIndices[0].Limb, x)

	initialMerkleCaps := []variables.FriMerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	// Seems like there is a bug in the emulated field code.
	// Add ZERO to all of the fri challenges values to reduce them.
	plonkZeta[0] = glApi.Add(plonkZeta[0], gl.Zero())
	plonkZeta[1] = glApi.Add(plonkZeta[1], gl.Zero())

	friChallenges.FriAlpha[0] = glApi.Add(friChallenges.FriAlpha[0], gl.Zero())
	friChallenges.FriAlpha[1] = glApi.Add(friChallenges.FriAlpha[1], gl.Zero())

	for i := 0; i < len(friChallenges.FriBetas); i++ {
		friChallenges.FriBetas[i][0] = glApi.Add(friChallenges.FriBetas[i][0], gl.Zero())
		friChallenges.FriBetas[i][1] = glApi.Add(friChallenges.FriBetas[i][1], gl.Zero())
	}

	friChallenges.FriPowResponse = glApi.Add(friChallenges.FriPowResponse, gl.Zero())

	for i := 0; i < len(friChallenges.FriQueryIndices); i++ {
		friChallenges.FriQueryIndices[i] = glApi.Add(friChallenges.FriQueryIndices[i], gl.Zero())
	}

	friChip.VerifyFriProof(
		friChip.GetInstance(plonkZeta),
		friChip.ToOpenings(proofWithPis.Proof.Openings),
		&friChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)

	return nil
}

func TestBlockFriVerification(t *testing.T) {
	assert := test.NewAssert(t)

	proofWithPIsFilename := "../testdata/test_circuit/proof_with_public_inputs.json"
	commonCircuitDataFilename := "../testdata/test_circuit/common_circuit_data.json"
	verifierOnlyCircuitDataFilename := "../testdata/test_circuit/verifier_only_circuit_data.json"

	proofWithPis, _ := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(proofWithPIsFilename))
	commonCircuitData := types.ReadCommonCircuitData(commonCircuitDataFilename)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(verifierOnlyCircuitDataFilename))

	testCase := func() {
		circuit := TestFriCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		witness := TestFriCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
