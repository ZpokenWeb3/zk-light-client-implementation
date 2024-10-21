package tests

import (
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"testing"

	"github.com/wormhole-foundation/example-near-light-client/types"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis, _ := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/test_circuit/proof_with_public_inputs.json"))
	t.Logf("%+v\n", proofWithPis)
}

func TestDeserializeVerifierOnlyCircuitData(t *testing.T) {
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/test_circuit/verifier_only_circuit_data.json"))
	t.Logf("%+v\n", verifierOnlyCircuitData)
}

func TestReadProofWithPublicInputs(t *testing.T) {
	types.ReadProofWithPublicInputs("../testdata/test_circuit/proof_with_public_inputs.json")
}

func TestReadVerifierOnlyCircuitData(t *testing.T) {
	types.ReadVerifierOnlyCircuitData("../testdata/test_circuit/verifier_only_circuit_data.json")
}
