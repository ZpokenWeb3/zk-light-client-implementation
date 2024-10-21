package tests

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

type TestGoldilocksRangeCheckCircuit struct {
	X frontend.Variable
}

func (c *TestGoldilocksRangeCheckCircuit) Define(api frontend.API) error {
	glApi := goldilocks.New(api)
	glApi.RangeCheck(goldilocks.NewVariable(c.X))
	return nil
}
func TestGoldilocksRangeCheck(t *testing.T) {
	assert := test.NewAssert(t)
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")

	var circuit, witness TestGoldilocksRangeCheckCircuit

	witness.X = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = 0
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = goldilocks.MODULUS
	assert.ProverFailed(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	one := big.NewInt(1)
	maxValidVal := new(big.Int).Sub(goldilocks.MODULUS, one)
	witness.X = maxValidVal
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type TestGoldilocksRangeCheckBenchmarkCircuit struct {
	X []frontend.Variable
}

func (c *TestGoldilocksRangeCheckBenchmarkCircuit) Define(api frontend.API) error {
	glApi := goldilocks.New(api)
	for _, x := range c.X {
		glApi.RangeCheck(goldilocks.NewVariable(x))
		glApi.Reduce(goldilocks.NewVariable(x))

	}
	return nil
}

func BenchmarkGoldilocksRangeCheck(b *testing.B) {
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")
	var sizes = []int{5, 10, 15}
	for i := 0; i < len(sizes); i++ {
		var circuit, witness TestGoldilocksRangeCheckBenchmarkCircuit
		circuit.X = make([]frontend.Variable, 2<<sizes[i])
		witness.X = make([]frontend.Variable, 2<<sizes[i])
		for j := 0; j < len(circuit.X); j++ {
			witness.X[j] = 1
		}
		p := profile.Start()
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
		if err != nil {
			fmt.Println("error in building circuit", err)
			os.Exit(1)
		}
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}
}

type TestGoldilocksMulAddCircuit struct {
	X, Y, Z        frontend.Variable
	ExpectedResult frontend.Variable
}

func (c *TestGoldilocksMulAddCircuit) Define(api frontend.API) error {
	glApi := goldilocks.New(api)
	calculateValue := glApi.MulAdd(goldilocks.NewVariable(c.X), goldilocks.NewVariable(c.Y), goldilocks.NewVariable(c.Z))
	api.AssertIsEqual(calculateValue.Limb, c.ExpectedResult)
	return nil
}

func TestGoldilocksMulAdd(t *testing.T) {
	assert := test.NewAssert(t)
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")
	var circuit, witness TestGoldilocksMulAddCircuit

	witness.X = 1
	witness.Y = 2
	witness.Z = 3
	witness.ExpectedResult = 5
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	bigOperand := new(big.Int).SetUint64(9223372036854775808)
	expectedValue, _ := new(big.Int).SetString("18446744068340842500", 10)

	witness.X = bigOperand
	witness.Y = bigOperand
	witness.Z = 3
	witness.ExpectedResult = expectedValue
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
