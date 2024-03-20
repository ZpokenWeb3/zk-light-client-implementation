package gates

import (
	"fmt"
	"regexp"
	"strconv"

	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/consensys/gnark/frontend"
)

var reducingGateRegex = regexp.MustCompile("ReducingGate { num_coeffs: (?P<numCoeffs>[0-9]+) }")

func deserializeReducingGate(parameters map[string]string) Gate {
	// Has the format "ReducingGate { num_coeffs: 33 }"
	numCoeffs, hasNumCoeffs := parameters["numCoeffs"]
	if !hasNumCoeffs {
		panic("Missing field num_coeffs in ReducingGate")
	}

	numCoeffsInt, err := strconv.Atoi(numCoeffs)
	if err != nil {
		panic("Invalid num_coeffs field in ReducingGate")
	}

	return NewReducingGate(uint64(numCoeffsInt))
}

type ReducingGate struct {
	numCoeffs uint64
}

const START_COEFFS_REDUCING_GATE = 3 * gl.D

func NewReducingGate(numCoeffs uint64) *ReducingGate {
	return &ReducingGate{
		numCoeffs: numCoeffs,
	}
}

func (g *ReducingGate) Id() string {
	return fmt.Sprintf("ReducingGate { num_coeffs: %d }", g.numCoeffs)
}

func (g *ReducingGate) wiresOutput() Range {
	return Range{0, gl.D}
}

func (g *ReducingGate) wiresAlpha() Range {
	return Range{gl.D, 2 * gl.D}
}

func (g *ReducingGate) wiresOldAcc() Range {
	return Range{2 * gl.D, 3 * gl.D}
}

func (g *ReducingGate) wiresCoeff() Range {
	return Range{START_COEFFS_REDUCING_GATE, START_COEFFS_REDUCING_GATE + g.numCoeffs}
}

func (g *ReducingGate) startAccs() uint64 {
	return START_COEFFS_REDUCING_GATE + g.numCoeffs
}

func (g *ReducingGate) wiresAccs(i uint64) Range {
	if i >= g.numCoeffs {
		panic("Accumulator index out of bounds")
	}

	if i == g.numCoeffs-1 {
		return g.wiresOutput()
	}

	return Range{g.startAccs() + gl.D*i, g.startAccs() + gl.D*(i+1)}
}

func (g *ReducingGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	alpha := vars.GetLocalExtAlgebra(g.wiresAlpha())
	oldAcc := vars.GetLocalExtAlgebra(g.wiresOldAcc())

	coeffs := []gl.QuadraticExtensionVariable{}
	coeffsRange := g.wiresCoeff()
	for i := coeffsRange.start; i < coeffsRange.end; i++ {
		coeffs = append(coeffs, vars.localWires[i])
	}

	accs := []gl.QuadraticExtensionAlgebraVariable{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		accs = append(accs, vars.GetLocalExtAlgebra(g.wiresAccs(i)))
	}

	constraints := []gl.QuadraticExtensionVariable{}
	acc := oldAcc
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeff := coeffs[i].ToQuadraticExtensionAlgebra()
		tmp := glApi.MulExtensionAlgebra(acc, alpha)
		tmp = glApi.AddExtensionAlgebra(tmp, coeff)
		tmp = glApi.SubExtensionAlgebra(tmp, accs[i])
		for j := 0; j < gl.D; j++ {
			constraints = append(constraints, tmp[j])
		}
		acc = accs[i]
	}

	return constraints
}
