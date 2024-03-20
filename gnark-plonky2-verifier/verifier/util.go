package verifier

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
	"math/big"
	"os"
	"time"
)

type VerifierCircuit struct {
	PublicInputs []gl.Variable `gnark:",public"`
	Proof        variables.Proof
	VerifierData variables.VerifierOnlyCircuitData

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData `gnark:"-"`
}

type CircuitFixed struct {
	PublicInputs      [4]frontend.Variable `gnark:",public"`
	VerifierData      variables.VerifierOnlyCircuitData
	ProofWithPis      variables.ProofWithPublicInputs
	CommonCircuitData types.CommonCircuitData `gnark:"-"`
}

func (c *CircuitFixed) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api, c.CommonCircuitData)
	verifierChip.Verify(c.ProofWithPis.Proof, c.ProofWithPis.PublicInputs, c.VerifierData)

	publicInputs := c.ProofWithPis.PublicInputs

	if len(publicInputs) != 16 {
		return fmt.Errorf("expected 16 public inputs, got %d", len(publicInputs))
	}
	for j := 0; j < 4; j++ {
		publicInputLimb := frontend.Variable(0)
		slicePub := publicInputs[j*4 : (j+1)*4]
		for i := 0; i < 4; i++ {
			pubU32 := slicePub[i].Limb
			pubByte := frontend.Variable(new(big.Int).SetUint64(1 << 32))
			publicInputLimb = api.Add(pubU32, api.Mul(pubByte, publicInputLimb))
		}
		api.AssertIsEqual(c.PublicInputs[j], publicInputLimb)
	}

	return nil
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api, c.CommonCircuitData)
	verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierData)
	return nil
}

func CompileVerifierCircuit(circuitPath string, system string) error {
	log := logger.Logger()
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(circuitPath + "/verifier_only_circuit_data.json"),
	)
	proofWithPis, _ := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(circuitPath + "/proof_with_public_inputs.json"),
	)
	commonCircuitData := types.ReadCommonCircuitData(circuitPath + "/common_circuit_data.json")

	circuit := VerifierCircuit{
		Proof:             proofWithPis.Proof,
		PublicInputs:      proofWithPis.PublicInputs,
		VerifierData:      verifierOnlyCircuitData,
		CommonCircuitData: commonCircuitData,
	}
	var builder frontend.NewBuilder
	if system == "plonk" {
		builder = scs.NewBuilder
	} else if system == "groth16" {
		builder = r1cs.NewBuilder
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}
	log.Info().Msg("Running circuit setup")
	start := time.Now()
	if system == "plonk" {
		srs, err := test.NewKZGSRS(r1cs)
		if err != nil {
			panic(err)
		}
		pk, vk, err := plonk.Setup(r1cs, srs)
		if err != nil {
			return err
		}
		err = SaveVerifierCircuitPlonk(circuitPath+"/build", r1cs, pk, vk)
		if err != nil {
			return err
		}
	} else if system == "groth16" {
		pk, vk, err := groth16.Setup(r1cs)
		if err != nil {
			return err
		}
		err = SaveVerifierCircuitGroth(circuitPath+"/build", r1cs, pk, vk)
		if err != nil {
			return err
		}
	}
	elapsed := time.Since(start)
	log.Info().Msg("Successfully ran circuit setup, time: " + elapsed.String())

	return fmt.Errorf("failed to save circuit: %w", err)
}

func SaveVerifierCircuitPlonk(path string, r1cs constraint.ConstraintSystem, pk plonk.ProvingKey, vk plonk.VerifyingKey) error {
	log := logger.Logger()
	os.MkdirAll(path, 0755)
	log.Info().Msg("Saving circuit constraints to " + path + "/r1cs.bin")
	r1csFile, err := os.Create(path + "/r1cs.bin")
	if err != nil {
		return fmt.Errorf("failed to create r1cs file: %w", err)
	}
	start := time.Now()
	r1cs.WriteTo(r1csFile)
	r1csFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully saved circuit constraints, time: " + elapsed.String())

	log.Info().Msg("Saving proving key to " + path + "/pk.bin")
	pkFile, err := os.Create(path + "/pk.bin")
	if err != nil {
		return fmt.Errorf("failed to create pk file: %w", err)
	}
	start = time.Now()
	pk.WriteRawTo(pkFile)
	pkFile.Close()
	elapsed = time.Since(start)
	log.Debug().Msg("Successfully saved proving key, time: " + elapsed.String())

	log.Info().Msg("Saving verifying key to " + path + "/vk.bin")
	vkFile, err := os.Create(path + "/vk.bin")
	if err != nil {
		return fmt.Errorf("failed to create vk file: %w", err)
	}
	start = time.Now()
	vk.WriteRawTo(vkFile)
	vkFile.Close()
	elapsed = time.Since(start)
	log.Info().Msg("Successfully saved verifying key, time: " + elapsed.String())

	start = time.Now()
	err = ExportPlonkVerifierSolidity(path, vk)
	elapsed = time.Since(start)
	log.Info().Msg("Successfully saved solidity file, time: " + elapsed.String())
	if err != nil {
		return fmt.Errorf("failed to create solidity file: %w", err)
	}
	return nil
}

func SaveVerifierCircuitGroth(path string, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	log := logger.Logger()
	os.MkdirAll(path, 0755)
	log.Info().Msg("Saving circuit constraints to " + path + "/r1cs.bin")
	r1csFile, err := os.Create(path + "/r1cs.bin")
	if err != nil {
		return fmt.Errorf("failed to create r1cs file: %w", err)
	}
	start := time.Now()
	r1cs.WriteTo(r1csFile)
	r1csFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully saved circuit constraints, time: " + elapsed.String())

	log.Info().Msg("Saving proving key to " + path + "/pk.bin")
	pkFile, err := os.Create(path + "/pk.bin")
	if err != nil {
		return fmt.Errorf("failed to create pk file: %w", err)
	}
	start = time.Now()
	pk.WriteRawTo(pkFile)
	pkFile.Close()
	elapsed = time.Since(start)
	log.Debug().Msg("Successfully saved proving key, time: " + elapsed.String())

	log.Info().Msg("Saving verifying key to " + path + "/vk.bin")
	vkFile, err := os.Create(path + "/vk.bin")
	if err != nil {
		return fmt.Errorf("failed to create vk file: %w", err)
	}
	start = time.Now()
	vk.WriteRawTo(vkFile)
	vkFile.Close()
	elapsed = time.Since(start)
	log.Info().Msg("Successfully saved verifying key, time: " + elapsed.String())

	start = time.Now()
	err = ExportGrothVerifierSolidity(path, vk)
	elapsed = time.Since(start)
	log.Info().Msg("Successfully saved solidity file, time: " + elapsed.String())
	if err != nil {
		return fmt.Errorf("failed to create solidity file: %w", err)
	}
	return nil
}

func GetPublicInputs(proofWithPis types.ProofWithPublicInputsRaw) *big.Int {
	publicInputs := proofWithPis.PublicInputs
	numPublicInputs := len(publicInputs)
	publicInputsBytes := make([]byte, numPublicInputs)
	for i, v := range publicInputs {
		publicInputsBytes[i] = byte(v & 0xFF)
	}
	input := new(big.Int).SetBytes(publicInputsBytes[0:numPublicInputs])
	return input
}

func ExportPlonkVerifierSolidity(path string, vk plonk.VerifyingKey) error {
	log := logger.Logger()
	// Create a new buffer and export the VerifyingKey into it as a Solidity contract and
	// convert the buffer content to a string for further manipulation.
	buf := new(bytes.Buffer)
	err := vk.ExportSolidity(buf)
	if err != nil {
		log.Err(err).Msg("failed to export verifying key to solidity")
		return err
	}
	content := buf.String()

	contractFile, err := os.Create(path + "/PlonkVerifier.sol")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(contractFile)
	// write the new content to the writer
	_, err = w.Write([]byte(content))
	if err != nil {
		return err
	}

	contractFile.Close()
	return err
}

func ExportGrothVerifierSolidity(path string, vk groth16.VerifyingKey) error {
	log := logger.Logger()
	// Create a new buffer and export the VerifyingKey into it as a Solidity contract and
	// convert the buffer content to a string for further manipulation.
	buf := new(bytes.Buffer)
	err := vk.ExportSolidity(buf)
	if err != nil {
		log.Err(err).Msg("failed to export verifying key to solidity")
		return err
	}
	content := buf.String()

	contractFile, err := os.Create(path + "/GrothVerifier.sol")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(contractFile)
	// write the new content to the writer
	_, err = w.Write([]byte(content))
	if err != nil {
		return err
	}

	contractFile.Close()
	return err
}

func LoadPlonkVerifierKey(path string) (plonk.VerifyingKey, error) {
	log := logger.Logger()
	vkFile, err := os.Open(path + "/vk.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to open vk file: %w", err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	start := time.Now()
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk file: %w", err)
	}
	vkFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded verifying key, time: " + elapsed.String())

	return vk, nil
}

func LoadPlonkProverData(path string) (constraint.ConstraintSystem, plonk.ProvingKey, error) {
	log := logger.Logger()
	r1csFile, err := os.Open(path + "/r1cs.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open r1cs file: %w", err)
	}
	r1cs := plonk.NewCS(ecc.BN254)
	start := time.Now()
	r1csReader := bufio.NewReader(r1csFile)
	_, err = r1cs.ReadFrom(r1csReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read r1cs file: %w", err)
	}
	r1csFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded constraint system, time: " + elapsed.String())

	pkFile, err := os.Open(path + "/pk.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	start = time.Now()
	pkReader := bufio.NewReader(pkFile)
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read pk file: %w", err)
	}
	pkFile.Close()
	elapsed = time.Since(start)
	log.Debug().Msg("Successfully loaded proving key, time: " + elapsed.String())

	return r1cs, pk, nil
}

func LoadGroth16VerifierKey(path string) (groth16.VerifyingKey, error) {
	log := logger.Logger()
	vkFile, err := os.Open(path + "/vk.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to open vk file: %w", err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	start := time.Now()
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk file: %w", err)
	}
	vkFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded verifying key, time: " + elapsed.String())

	return vk, nil
}

func LoadGroth16ProverData(path string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	log := logger.Logger()
	r1csFile, err := os.Open(path + "/r1cs.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open r1cs file: %w", err)
	}
	r1cs := groth16.NewCS(ecc.BN254)
	start := time.Now()
	r1csReader := bufio.NewReader(r1csFile)
	_, err = r1cs.ReadFrom(r1csReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read r1cs file: %w", err)
	}
	r1csFile.Close()
	elapsed := time.Since(start)
	log.Debug().Msg("Successfully loaded constraint system, time: " + elapsed.String())

	pkFile, err := os.Open(path + "/pk.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	start = time.Now()
	pkReader := bufio.NewReader(pkFile)
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read pk file: %w", err)
	}
	pkFile.Close()
	elapsed = time.Since(start)
	log.Debug().Msg("Successfully loaded proving key, time: " + elapsed.String())

	return r1cs, pk, nil
}
