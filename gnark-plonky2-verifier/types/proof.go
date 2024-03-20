package types

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Groth16Proof struct {
	A     [2]*big.Int    `json:"a"`
	B     [2][2]*big.Int `json:"b"`
	C     [2]*big.Int    `json:"c"`
	Input hexutil.Bytes  `json:"input,omitempty"`
}

func (g *Groth16Proof) Export(file string) error {
	proofFile, err := os.Create(file)
	if err != nil {
		panic(fmt.Errorf("failed to create file: %w", err))
	}

	defer proofFile.Close()
	jsonString, err := json.Marshal(g)
	if err != nil {
		panic(fmt.Errorf("failed to marshal output: %w", err))
	}
	_, err = proofFile.Write(jsonString)
	if err != nil {
		panic(fmt.Errorf("failed to write data: %w", err))
	}

	return nil
}

type PlonkProof struct {
	Proof hexutil.Bytes `json:"proof"`
	Input hexutil.Bytes `json:"input,omitempty"`
}

func (g *PlonkProof) Export(file string) error {
	proofFile, err := os.Create(file)
	if err != nil {
		panic(fmt.Errorf("failed to create file: %w", err))
	}

	defer proofFile.Close()
	jsonString, err := json.Marshal(g)
	if err != nil {
		panic(fmt.Errorf("failed to marshal output: %w", err))
	}
	_, err = proofFile.Write(jsonString)
	if err != nil {
		panic(fmt.Errorf("failed to write data: %w", err))
	}

	return nil
}
