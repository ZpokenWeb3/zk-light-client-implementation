package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var constantGateRegex = regexp.MustCompile("ConstantGate { num_consts: (?P<numConsts>[0-9]+) }")

func deserializeConstantGate(parameters map[string]string) Gate {
	// Has the format "ConstantGate { num_consts: 2 }"
	numConsts, hasNumConsts := parameters["numConsts"]
	if !hasNumConsts {
		panic("Missing field num_consts in ConstantGate")
	}

	numConstsInt, err := strconv.Atoi(numConsts)
	if err != nil {
		panic("Invalid num_consts field in ConstantGate")
	}

	return NewConstantGate(uint64(numConstsInt))
}

type ConstantGate struct {
	numConsts uint64
}

func NewConstantGate(numConsts uint64) *ConstantGate {
	return &ConstantGate{
		numConsts: numConsts,
	}
}

func (g *ConstantGate) Id() string {
	return fmt.Sprintf("ConstantGate { num_consts: %d }", g.numConsts)
}

func (g *ConstantGate) ConstInput(i uint64) uint64 {
	if i >= g.numConsts {
		panic("Invalid constant index")
	}
	return i
}

func (g *ConstantGate) WireOutput(i uint64) uint64 {
	if i >= g.numConsts {
		panic("Invalid wire index")
	}
	return i
}

func (g *ConstantGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	constraints := []gl.QuadraticExtensionVariable{}

	for i := uint64(0); i < g.numConsts; i++ {
		constraints = append(constraints, glApi.SubExtension(vars.localConstants[g.ConstInput(i)], vars.localWires[g.WireOutput(i)]))
	}

	return constraints
}
