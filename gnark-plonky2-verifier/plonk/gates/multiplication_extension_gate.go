package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var mulExtensionGateRegex = regexp.MustCompile("MulExtensionGate { num_ops: (?P<numOps>[0-9]+) }")

func deserializeMulExtensionGate(parameters map[string]string) Gate {
	// Has the format "MulExtensionGate { num_ops: 13 }"
	numOps, hasNumOps := parameters["numOps"]
	if !hasNumOps {
		panic("Missing field num_ops in MulExtensionGate")
	}

	numOpsInt, err := strconv.Atoi(numOps)
	if err != nil {
		panic("Invalid num_ops field in MulExtensionGate")
	}

	return NewMultiplicationExtensionGate(uint64(numOpsInt))
}

type MultiplicationExtensionGate struct {
	numOps uint64
}

func NewMultiplicationExtensionGate(numOps uint64) *MultiplicationExtensionGate {
	return &MultiplicationExtensionGate{
		numOps: numOps,
	}
}

func (g *MultiplicationExtensionGate) Id() string {
	return fmt.Sprintf("MulExtensionGate { num_ops: %d }", g.numOps)
}

func (g *MultiplicationExtensionGate) wiresIthMultiplicand0(i uint64) Range {
	return Range{3 * gl.D * i, 3*gl.D*i + gl.D}
}

func (g *MultiplicationExtensionGate) wiresIthMultiplicand1(i uint64) Range {
	return Range{3*gl.D*i + gl.D, 3*gl.D*i + 2*gl.D}
}

func (g *MultiplicationExtensionGate) wiresIthOutput(i uint64) Range {
	return Range{3*gl.D*i + 2*gl.D, 3*gl.D*i + 3*gl.D}
}

func (g *MultiplicationExtensionGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	const0 := vars.localConstants[0]
	constraints := []gl.QuadraticExtensionVariable{}
	for i := uint64(0); i < g.numOps; i++ {
		multiplicand0 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand0(i))
		multiplicand1 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand1(i))
		output := vars.GetLocalExtAlgebra(g.wiresIthOutput(i))

		mul := glApi.MulExtensionAlgebra(multiplicand0, multiplicand1)
		computed_output := glApi.ScalarMulExtensionAlgebra(const0, mul)

		diff := glApi.SubExtensionAlgebra(output, computed_output)
		for j := 0; j < gl.D; j++ {
			constraints = append(constraints, diff[j])
		}
	}
	return constraints
}
