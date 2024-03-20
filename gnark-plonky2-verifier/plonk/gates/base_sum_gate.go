package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var baseSumGateRegex = regexp.MustCompile(`BaseSumGate { num_limbs: (?P<numLimbs>[0-9]+) } \+ Base: (?P<base>[0-9]+)`)

func deserializeBaseSumGate(parameters map[string]string) Gate {

	// Has the format "BaseSumGate { num_limbs: 32 } + Base: 2"
	numLimbs, hasNumLimbs := parameters["numLimbs"]
	base, hasBase := parameters["base"]
	if !hasNumLimbs || !hasBase {
		panic("Missing field num_limbs or base in BaseSumGate")
	}

	numLimbsInt, err := strconv.Atoi(numLimbs)
	if err != nil {
		panic("Invalid num_limbs field in BaseSumGate")
	}

	baseInt, err := strconv.Atoi(base)
	if err != nil {
		panic("Invalid base field in BaseSumGate")
	}

	return NewBaseSumGate(uint64(numLimbsInt), uint64(baseInt))
}

const (
	BASESUM_GATE_WIRE_SUM    = 0
	BASESUM_GATE_START_LIMBS = 1
)

type BaseSumGate struct {
	numLimbs uint64
	base     uint64
}

func NewBaseSumGate(numLimbs uint64, base uint64) *BaseSumGate {
	return &BaseSumGate{
		numLimbs: numLimbs,
		base:     base,
	}
}

func (g *BaseSumGate) Id() string {
	return fmt.Sprintf("BaseSumGate { num_limbs: %d } + Base: %d", g.numLimbs, g.base)
}

func (g *BaseSumGate) limbs() []uint64 {
	limbIndices := make([]uint64, g.numLimbs)
	for i := uint64(0); i < g.numLimbs; i++ {
		limbIndices[i] = uint64(BASESUM_GATE_START_LIMBS + i)
	}

	return limbIndices
}

func (g *BaseSumGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	sum := vars.localWires[BASESUM_GATE_WIRE_SUM]
	limbs := make([]gl.QuadraticExtensionVariable, g.numLimbs)
	limbIndices := g.limbs()
	for i, limbIdx := range limbIndices {
		limbs[i] = vars.localWires[limbIdx]
	}

	baseQe := gl.NewQuadraticExtensionVariable(gl.NewVariable(g.base), gl.Zero())
	computedSum := glApi.ReduceWithPowers(
		limbs,
		baseQe,
	)

	var constraints []gl.QuadraticExtensionVariable
	constraints = append(constraints, glApi.SubExtension(computedSum, sum))
	for _, limb := range limbs {
		acc := gl.OneExtension()
		for i := uint64(0); i < g.base; i++ {
			difference := glApi.SubExtension(limb, gl.NewQuadraticExtensionVariable(gl.NewVariable(i), gl.Zero()))
			acc = glApi.MulExtension(acc, difference)
		}
		constraints = append(constraints, acc)
	}

	return constraints
}
