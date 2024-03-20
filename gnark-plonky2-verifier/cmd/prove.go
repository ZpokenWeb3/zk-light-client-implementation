package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"github.com/wormhole-foundation/example-near-light-client/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"math/big"
	"os"
	"time"
)

// proveCmd represents the proof command
var proveCmd = &cobra.Command{
	Use:   "prove",
	Short: "runs a proof generation in gnark, and verify it, writing to json file input and hex bytes proof",
	Run:   prove,
}

func prove(cmd *cobra.Command, args []string) {
	path := fBaseDir + "/build"

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(fBaseDir + "/verifier_only_circuit_data.json"),
	)
	proofWithPis := types.ReadProofWithPublicInputs(fBaseDir + "/proof_with_public_inputs.json")
	proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofWithPis)
	assignment := &verifier.VerifierCircuit{
		Proof:        proofWithPisVariable.Proof,
		VerifierData: verifierOnlyCircuitData,
		PublicInputs: proofWithPisVariable.PublicInputs,
	}
	if system == "plonk" {
		r1cs, pk, err := verifier.LoadPlonkProverData(path)
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
		start := time.Now()

		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Printf("failed to generate witness: %w", err)
		}
		elapsed := time.Since(start)
		log.Info().Msg("Successfully generated witness, time: " + elapsed.String())

		log.Info().Msg("Creating proof")
		start = time.Now()
		proof, err := plonk.Prove(r1cs, pk, witness)
		if err != nil {
			fmt.Printf("failed to create proof: %w", err)
		}
		elapsed = time.Since(start)
		log.Info().Msg("Successfully created proof, time: " + elapsed.String())
		_proof := proof.(*plonk_bn254.Proof)
		log.Info().Msg("Saving proof to proof.json")
		serializedProof := _proof.MarshalSolidity()
		log.Printf("Proof len: %d", len(serializedProof))
		jsonProofWithWitness, err := json.Marshal(struct {
			PublicInputs []uint64      `json:"inputs"`
			Proof        hexutil.Bytes `json:"proof"`
		}{
			PublicInputs: pis,
			Proof:        serializedProof,
		})
		if err != nil {
			fmt.Printf("failed to marshal proof with witness: %w", err)
		}
		proofFile, err := os.Create("proof_with_witness.json")
		if err != nil {
			fmt.Printf("failed to create proof_with_witness file: %w", err)
		}
		_, err = proofFile.Write(jsonProofWithWitness)
		if err != nil {
			fmt.Printf("failed to write proof_with_witness file: %w", err)
		}
		proofFile.Close()
		log.Info().Msg("Successfully saved proof_with_witness")
	} else if system == "groth16" {
		r1cs, pk, err := verifier.LoadGroth16ProverData(path)
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Printf("failed to generate witness: %w", err)
		}
		start := time.Now()
		proof, _ := groth16.Prove(r1cs, pk, witness)
		elapsed := time.Since(start)
		log.Info().Msg("Successfully created proof, time: " + elapsed.String())

		const fpSize = 4 * 8
		buf := new(bytes.Buffer)
		proof.WriteRawTo(buf)
		proofBytes := buf.Bytes()

		proofs := make([]string, 8)
		// Print out the proof
		for i := 0; i < 8; i++ {
			proofs[i] = new(big.Int).SetBytes(proofBytes[i*fpSize : (i+1)*fpSize]).String()
		}
		jsonProofWithWitness, err := json.Marshal(struct {
			PublicInputs []uint64 `json:"inputs"`
			Proof        []string `json:"proof"`
		}{
			PublicInputs: pis,
			Proof:        proofs,
		})
		if err != nil {
			fmt.Printf("failed to marshal proof with witness: %w", err)
		}
		proofFile, err := os.Create("proof_with_witness.json")
		if err != nil {
			fmt.Printf("failed to create proof_with_witness file: %w", err)
		}
		_, err = proofFile.Write(jsonProofWithWitness)
		if err != nil {
			fmt.Printf("failed to write proof_with_witness file: %w", err)
		}
		proofFile.Close()
		log.Debug().Msg("Successfully saved proof_with_witness")
	}
}

func init() {
	rootCmd.AddCommand(proveCmd)
	proveCmd.Flags().StringVar(&system, "system", "", "proof system for proving (groth16 or plonk)")
}
