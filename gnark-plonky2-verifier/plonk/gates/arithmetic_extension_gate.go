package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var arithmeticExtensionGateRegex = regexp.MustCompile("ArithmeticExtensionGate { num_ops: (?P<numOps>[0-9]+) }")

func deserializeExtensionArithmeticGate(parameters map[string]string) Gate {
	// Has the format "ArithmeticExtensionGate { num_ops: 10 }"
	numOps, hasNumOps := parameters["numOps"]
	if !hasNumOps {
		panic("Missing field num_ops in ArithmeticExtensionGate")
	}

	numOpsInt, err := strconv.Atoi(numOps)
	if err != nil {
		panic("Invalid num_ops field in ArithmeticExtensionGate")
	}

	return NewArithmeticExtensionGate(uint64(numOpsInt))
}

type ArithmeticExtensionGate struct {
	numOps uint64
}

func NewArithmeticExtensionGate(numOps uint64) *ArithmeticExtensionGate {
	return &ArithmeticExtensionGate{
		numOps: numOps,
	}
}

func (g *ArithmeticExtensionGate) Id() string {
	return fmt.Sprintf("ArithmeticExtensionGate { num_ops: %d }", g.numOps)
}

func (g *ArithmeticExtensionGate) wiresIthMultiplicand0(i uint64) Range {
	return Range{4 * gl.D * i, 4*gl.D*i + gl.D}
}

func (g *ArithmeticExtensionGate) wiresIthMultiplicand1(i uint64) Range {
	return Range{4*gl.D*i + gl.D, 4*gl.D*i + 2*gl.D}
}

func (g *ArithmeticExtensionGate) wiresIthAddend(i uint64) Range {
	return Range{4*gl.D*i + 2*gl.D, 4*gl.D*i + 3*gl.D}
}

func (g *ArithmeticExtensionGate) wiresIthOutput(i uint64) Range {
	return Range{4*gl.D*i + 3*gl.D, 4*gl.D*i + 4*gl.D}
}

func (g *ArithmeticExtensionGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	const0 := vars.localConstants[0]
	const1 := vars.localConstants[1]

	constraints := []gl.QuadraticExtensionVariable{}
	for i := uint64(0); i < g.numOps; i++ {
		multiplicand0 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand0(i))
		multiplicand1 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand1(i))
		addend := vars.GetLocalExtAlgebra(g.wiresIthAddend(i))
		output := vars.GetLocalExtAlgebra(g.wiresIthOutput(i))

		mul := glApi.MulExtensionAlgebra(multiplicand0, multiplicand1)
		scaled_mul := glApi.ScalarMulExtensionAlgebra(const0, mul)
		computed_output := glApi.ScalarMulExtensionAlgebra(const1, addend)
		computed_output = glApi.AddExtensionAlgebra(computed_output, scaled_mul)

		diff := glApi.SubExtensionAlgebra(output, computed_output)
		for j := 0; j < gl.D; j++ {
			constraints = append(constraints, diff[j])
		}
	}

	return constraints
}
