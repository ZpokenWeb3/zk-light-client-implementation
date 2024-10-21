package tests

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"github.com/wormhole-foundation/example-near-light-client/verifier"
	"testing"
)

func TestBlockVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		plonky2Circuit := "test_circuit"
		commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")

		proofWithPis, _ := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

		circuit := verifier.VerifierCircuit{
			Proof:             proofWithPis.Proof,
			PublicInputs:      proofWithPis.PublicInputs,
			VerifierData:      verifierOnlyCircuitData,
			CommonCircuitData: commonCircuitData,
		}

		witness := verifier.VerifierCircuit{
			Proof:             proofWithPis.Proof,
			PublicInputs:      proofWithPis.PublicInputs,
			VerifierData:      verifierOnlyCircuitData,
			CommonCircuitData: commonCircuitData,
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	testCase()
}
