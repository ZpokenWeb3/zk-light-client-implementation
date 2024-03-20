package gates

import (
	"fmt"
	"regexp"
	"strconv"

	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/consensys/gnark/frontend"
)

var arithmeticGateRegex = regexp.MustCompile("ArithmeticGate { num_ops: (?P<numOps>[0-9]+) }")

func deserializeArithmeticGate(parameters map[string]string) Gate {
	// Has the format "ArithmeticGate { num_ops: 10 }"

	numOps, hasNumOps := parameters["numOps"]
	if !hasNumOps {
		panic("no num_ops field in ArithmeticGate")
	}

	numOpsInt, err := strconv.Atoi(numOps)
	if err != nil {
		panic("Invalid num_ops field in ArithmeticGate")
	}

	return NewArithmeticGate(uint64(numOpsInt))
}

type ArithmeticGate struct {
	numOps uint64
}

func NewArithmeticGate(numOps uint64) *ArithmeticGate {
	return &ArithmeticGate{
		numOps: numOps,
	}
}

func (g *ArithmeticGate) Id() string {
	return fmt.Sprintf("ArithmeticGate { num_ops: %d }", g.numOps)
}

func (g *ArithmeticGate) WireIthMultiplicand0(i uint64) uint64 {
	return 4 * i
}

func (g *ArithmeticGate) WireIthMultiplicand1(i uint64) uint64 {
	return 4*i + 1
}

func (g *ArithmeticGate) WireIthAddend(i uint64) uint64 {
	return 4*i + 2
}

func (g *ArithmeticGate) WireIthOutput(i uint64) uint64 {
	return 4*i + 3
}

func (g *ArithmeticGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	const0 := vars.localConstants[0]
	const1 := vars.localConstants[1]

	constraints := []gl.QuadraticExtensionVariable{}
	for i := uint64(0); i < g.numOps; i++ {
		multiplicand0 := vars.localWires[g.WireIthMultiplicand0(i)]
		multiplicand1 := vars.localWires[g.WireIthMultiplicand1(i)]
		addend := vars.localWires[g.WireIthAddend(i)]
		output := vars.localWires[g.WireIthOutput(i)]

		computedOutput := glApi.AddExtension(
			glApi.MulExtension(glApi.MulExtension(multiplicand0, multiplicand1), const0),
			glApi.MulExtension(addend, const1),
		)

		constraints = append(constraints, glApi.SubExtension(output, computedOutput))
	}

	return constraints
}
