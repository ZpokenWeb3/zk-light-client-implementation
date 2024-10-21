package tests

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/wormhole-foundation/example-near-light-client/plonk"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"github.com/wormhole-foundation/example-near-light-client/verifier"
	"testing"
)

type TestPlonkCircuit struct {
	ProofWithPis            variables.ProofWithPublicInputs   `gnark:",public"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:",public"`
	CommonCircuitData       types.CommonCircuitData
}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	commonCircuitData := circuit.CommonCircuitData
	verifierOnlyCircuitData := circuit.VerifierOnlyCircuitData
	proofWithPis := circuit.ProofWithPis

	verifierChip := verifier.NewVerifierChip(api, commonCircuitData)
	publicInputsHash := verifierChip.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := verifierChip.GetChallenges(proofWithPis.Proof, publicInputsHash, verifierOnlyCircuitData)

	plonkChip := plonk.NewPlonkChip(
		api,
		commonCircuitData,
	)

	plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)
	return nil
}

func TestPlonkNearBlock(t *testing.T) {
	assert := test.NewAssert(t)

	proofWithPIsFilename := "../testdata/test_circuit/proof_with_public_inputs.json"
	commonCircuitDataFilename := "../testdata/test_circuit/common_circuit_data.json"
	verifierOnlyCircuitDataFilename := "../testdata/test_circuit/verifier_only_circuit_data.json"

	proofWithPis, _ := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(proofWithPIsFilename))
	commonCircuitData := types.ReadCommonCircuitData(commonCircuitDataFilename)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(verifierOnlyCircuitDataFilename))

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		witness := TestPlonkCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
