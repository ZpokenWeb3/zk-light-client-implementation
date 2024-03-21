package cmd

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"github.com/wormhole-foundation/example-near-light-client/verifier"
	"math/big"
	"net/http"
)

// proveCmd represents the proof command
var proveCmd = &cobra.Command{
	Use:   "web-api",
	Short: "runs a web server for proof generation in gnark, and verify it, writing to json file input and hex bytes proof",
	Run:   runApi,
}

func healthCheck(c *gin.Context) {
	response := gin.H{
		"status":  "ok",
		"message": "Health check passed",
	}

	c.JSON(http.StatusOK, response)
}

const fpSize = 4 * 8

func generateProof(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		var proofReq ProofRequest

		if err := c.ShouldBindJSON(&proofReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		proofWithPisSerialized := types.ReadProofWithPublicInputsFromRequest(proofReq.ProofWithPis)
		verifierSerialized := types.ReadVerifierOnlyCircuitDataFromRequest(proofReq.VerifierCircuitData)
		proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofWithPisSerialized)
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierSerialized)
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

		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate witness: %v", err)})
			return
		}

		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate proof: %v", err)})
			return
		}

		publicWitness, _ := witness.Public()
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to verify proof: %v", err)})
			return
		}

		buf := new(bytes.Buffer)
		proof.WriteRawTo(buf)
		proofBytes := buf.Bytes()

		proofs := make([]string, 8)

		for i := 0; i < 8; i++ {
			proofs[i] = new(big.Int).SetBytes(proofBytes[i*fpSize : (i+1)*fpSize]).String()
		}

		c.JSON(http.StatusOK, gin.H{
			"inputs": bigIntPis,
			"proof":  proofs,
		})
	}
}

type ProofRequest struct {
	ID                  string `json:"id"`
	ProofWithPis        []byte `json:"proofWithPis"`
	VerifierCircuitData []byte `json:"verifierData"`
}

func runApi(cmd *cobra.Command, args []string) {
	path := "api-build"
	vk, _ := verifier.LoadGroth16VerifierKey(path)
	r1cs, pk, _ := verifier.LoadGroth16ProverData(path)
	//gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.GET("/health", healthCheck)
	router.POST("/proof", generateProof(r1cs, pk, vk))
	router.Run("0.0.0.0:8010")
}

func init() {
	rootCmd.AddCommand(proveCmd)
}
