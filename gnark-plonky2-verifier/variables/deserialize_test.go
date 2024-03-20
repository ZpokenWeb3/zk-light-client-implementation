package variables

import (
	"testing"

	"github.com/wormhole-foundation/example-near-light-client/types"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis, _ := DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/decode_block/proof_with_public_inputs.json"))
	t.Logf("%+v\n", proofWithPis)
}

func TestDeserializeVerifierOnlyCircuitData(t *testing.T) {
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/decode_block/verifier_only_circuit_data.json"))
	t.Logf("%+v\n", verifierOnlyCircuitData)
}
