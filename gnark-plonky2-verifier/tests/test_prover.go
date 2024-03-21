package tests

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/test"
    "github.com/rs/zerolog/log"
    "github.com/wormhole-foundation/example-near-light-client/types"
    "github.com/wormhole-foundation/example-near-light-client/variables"
    "github.com/wormhole-foundation/example-near-light-client/verifier"
    "math/big"
    "os"
    "testing"
    "time"
)

func TestBlockCircuitProver(t *testing.T) {
    assert := test.NewAssert(t)
    path := "api-build"
    fBaseDir := flag.String("plonky2-circuit", "testdata/test_circuit", "plonky2 circuit to benchmark")
    flag.Parse()
    verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
        types.ReadVerifierOnlyCircuitData(*fBaseDir + "/verifier_only_circuit_data.json"),
    )
    proofWithPis := types.ReadProofWithPublicInputs(*fBaseDir + "/proof_with_public_inputs.json")
    proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofWithPis)
    var publicInputsConverted [4]frontend.Variable
    var bigIntPis [4]string
    for j := 0; j < 4; j++ {
        limbs := make([]byte, 16)
        slicePub := pis[j*4 : (j+1)*4]
        for i := 0; i < 4; i++ {
            offset := i * 4
            limbs[offset] = byte((slicePub[i] >> 24) & 0xFF)
            limbs[offset+1] = byte((slicePub[i] >> 16) & 0xFF)
            limbs[offset+2] = byte((slicePub[i] >> 8) & 0xFF)
            limbs[offset+3] = byte(slicePub[i] & 0xFF)
        }
        bigIntValue := new(big.Int).SetBytes(limbs)
        bigIntPis[j] = bigIntValue.String()
        publicInputsConverted[j] = frontend.Variable(bigIntValue)
    }
    assignment := &verifier.CircuitFixed{
        ProofWithPis: proofWithPisVariable,
        VerifierData: verifierOnlyCircuitData,
        PublicInputs: publicInputsConverted,
    }
    r1cs, pk, err := verifier.LoadGroth16ProverData(path)
    if err != nil {
        fmt.Printf("error: %s\n", err.Error())
    }
    assert.NoError(err)
    witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
    if err != nil {
        fmt.Printf("failed to generate witness: %w", err)
    }
    assert.NoError(err)
    start := time.Now()
    proof, err := groth16.Prove(r1cs, pk, witness)
    assert.NoError(err)
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
        PublicInputs [4]string `json:"inputs"`
        Proof        []string  `json:"proof"`
    }{
        PublicInputs: bigIntPis,
        Proof:        proofs,
    })
    if err != nil {
        fmt.Printf("failed to marshal proof with witness: %w", err)
    }
    assert.NoError(err)
    proofFile, err := os.Create("proof_with_witness.json")
    if err != nil {
        fmt.Printf("failed to create proof_with_witness file: %w", err)
    }
    assert.NoError(err)
    _, err = proofFile.Write(jsonProofWithWitness)
    if err != nil {
        fmt.Printf("failed to write proof_with_witness file: %w", err)
    }
    assert.NoError(err)
    proofFile.Close()
    log.Debug().Msg("Successfully saved proof_with_witness")
}
