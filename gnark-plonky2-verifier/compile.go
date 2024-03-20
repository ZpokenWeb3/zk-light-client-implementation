package main

import (
	"flag"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"github.com/wormhole-foundation/example-near-light-client/verifier"
)

func main() {
	circuitPath := flag.String("plonky2-circuit", "testdata/test_circuit", "plonky2 circuit to benchmark")
	flag.Parse()
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(*circuitPath + "/verifier_only_circuit_data.json"),
	)
	proofWithPis, _ := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(*circuitPath + "/proof_with_public_inputs.json"),
	)
	commonCircuitData := types.ReadCommonCircuitData(*circuitPath + "/common_circuit_data.json")

	circuit := verifier.CircuitFixed{
		ProofWithPis: proofWithPis,
		PublicInputs: [4]frontend.Variable{new(frontend.Variable), new(frontend.Variable),
			new(frontend.Variable), new(frontend.Variable)},
		VerifierData:      verifierOnlyCircuitData,
		CommonCircuitData: commonCircuitData,
	}
	var builder frontend.NewBuilder
	builder = r1cs.NewBuilder
	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)
	_ = verifier.SaveVerifierCircuitGroth("api-build", r1cs, pk, vk)
}
