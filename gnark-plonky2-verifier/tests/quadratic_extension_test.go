package tests

import (
	"github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestQuadraticExtensionMulCircuit struct {
	Operand1       goldilocks.QuadraticExtensionVariable
	Operand2       goldilocks.QuadraticExtensionVariable
	ExpectedResult goldilocks.QuadraticExtensionVariable
}

func (c *TestQuadraticExtensionMulCircuit) Define(api frontend.API) error {
	glApi := goldilocks.New(api)
	actualRes := glApi.MulExtension(c.Operand1, c.Operand2)
	glApi.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	glApi.AssertIsEqual(actualRes[1], c.ExpectedResult[1])
	return nil
}

func TestQuadraticExtensionMul4(t *testing.T) {
	assert := test.NewAssert(t)
	operand1 := goldilocks.QuadraticExtensionVariable{
		goldilocks.NewVariable("4994088319481652598"),
		goldilocks.NewVariable("16489566008211790727"),
	}
	operand2 := goldilocks.QuadraticExtensionVariable{
		goldilocks.NewVariable("3797605683985595697"),
		goldilocks.NewVariable("13424401189265534004"),
	}
	expectedResult := goldilocks.QuadraticExtensionVariable{
		goldilocks.NewVariable("15052319864161058789"),
		goldilocks.NewVariable("16841416332519902625"),
	}
	circuit := TestQuadraticExtensionMulCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	witness := TestQuadraticExtensionMulCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// Test for quadratic extension division
type TestQuadraticExtensionDivCircuit struct {
	Operand1       goldilocks.QuadraticExtensionVariable
	Operand2       goldilocks.QuadraticExtensionVariable
	ExpectedResult goldilocks.QuadraticExtensionVariable
}

func (c *TestQuadraticExtensionDivCircuit) Define(api frontend.API) error {
	glAPI := goldilocks.New(api)
	actualRes, _ := glAPI.DivExtension(c.Operand1, c.Operand2)
	glAPI.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	glAPI.AssertIsEqual(actualRes[1], c.ExpectedResult[1])
	return nil
}

func TestQuadraticExtensionDiv(t *testing.T) {
	assert := test.NewAssert(t)
	operand1 := goldilocks.QuadraticExtensionVariable{
		goldilocks.NewVariable("4994088319481652598"),
		goldilocks.NewVariable("16489566008211790727"),
	}
	operand2 := goldilocks.QuadraticExtensionVariable{
		goldilocks.NewVariable("7166004739148609569"),
		goldilocks.NewVariable("14655965871663555016"),
	}
	expectedResult := goldilocks.QuadraticExtensionVariable{
		goldilocks.NewVariable("15052319864161058789"),
		goldilocks.NewVariable("16841416332519902625"),
	}
	circuit := TestQuadraticExtensionDivCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	witness := TestQuadraticExtensionDivCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
