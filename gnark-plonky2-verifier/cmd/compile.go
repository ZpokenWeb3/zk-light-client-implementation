package cmd

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/spf13/cobra"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"github.com/wormhole-foundation/example-near-light-client/verifier"
)

var compileCmd = &cobra.Command{
	Use:   "compile",
	Short: "compile build circuit data(pv, vk, solidity contract) from plonky2 proof",
	Run:   compile,
}

func compile(cmd *cobra.Command, args []string) {
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(fBaseDir + "/verifier_only_circuit_data.json"),
	)
	proofWithPis, _ := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(fBaseDir + "/proof_with_public_inputs.json"),
	)
	
	commonCircuitData := types.ReadCommonCircuitData(fBaseDir + "/common_circuit_data.json")

	circuit := verifier.CircuitFixed{
		ProofWithPis: proofWithPis,
		PublicInputs: [4]frontend.Variable{new(frontend.Variable), new(frontend.Variable),
			new(frontend.Variable), new(frontend.Variable)},
		VerifierData:      verifierOnlyCircuitData,
		CommonCircuitData: commonCircuitData,
	}
	var builder frontend.NewBuilder = r1cs.NewBuilder
	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	
	pk, vk, _ := groth16.Setup(r1cs)

	_ = verifier.SaveVerifierCircuitGroth("api-build", r1cs, pk, vk)
}

func init() {
	rootCmd.AddCommand(compileCmd)
}
