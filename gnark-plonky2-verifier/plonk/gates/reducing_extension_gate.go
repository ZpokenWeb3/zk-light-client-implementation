package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var reducingExtensionGateRegex = regexp.MustCompile("ReducingExtensionGate { num_coeffs: (?P<numCoeffs>[0-9]+) }")

func deserializeReducingExtensionGate(parameters map[string]string) Gate {
	// Has the format "ReducingExtensionGate { num_coeffs: 33 }"
	numCoeffs, hasNumCoeffs := parameters["numCoeffs"]
	if !hasNumCoeffs {
		panic("Missing field num_coeffs in ReducingExtensionGate")
	}

	numCoeffsInt, err := strconv.Atoi(numCoeffs)
	if err != nil {
		panic("Invalid num_coeffs field in ReducingExtensionGate")
	}

	return NewReducingExtensionGate(uint64(numCoeffsInt))
}

type ReducingExtensionGate struct {
	numCoeffs uint64
}

const START_COEFFS_REDUCING_EXTENSION_GATE = 3 * gl.D

func NewReducingExtensionGate(numCoeffs uint64) *ReducingExtensionGate {
	return &ReducingExtensionGate{
		numCoeffs: numCoeffs,
	}
}

func (g *ReducingExtensionGate) Id() string {
	return fmt.Sprintf("ReducingExtensionGate { num_coeffs: %d }", g.numCoeffs)
}

func (g *ReducingExtensionGate) wiresOutput() Range {
	return Range{0, gl.D}
}

func (g *ReducingExtensionGate) wiresAlpha() Range {
	return Range{gl.D, 2 * gl.D}
}

func (g *ReducingExtensionGate) wiresOldAcc() Range {
	return Range{2 * gl.D, 3 * gl.D}
}

func (g *ReducingExtensionGate) wiresCoeff(i uint64) Range {
	return Range{START_COEFFS_REDUCING_EXTENSION_GATE + gl.D*i, START_COEFFS_REDUCING_EXTENSION_GATE + gl.D*(i+1)}
}

func (g *ReducingExtensionGate) startAccs() uint64 {
	return START_COEFFS_REDUCING_EXTENSION_GATE + g.numCoeffs*gl.D
}

func (g *ReducingExtensionGate) wiresAccs(i uint64) Range {
	if i >= g.numCoeffs {
		panic("Accumulator index out of bounds")
	}

	if i == g.numCoeffs-1 {
		return g.wiresOutput()
	}

	return Range{g.startAccs() + gl.D*i, g.startAccs() + gl.D*(i+1)}
}

func (g *ReducingExtensionGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	alpha := vars.GetLocalExtAlgebra(g.wiresAlpha())
	oldAcc := vars.GetLocalExtAlgebra(g.wiresOldAcc())

	coeffs := []gl.QuadraticExtensionAlgebraVariable{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeffs = append(coeffs, vars.GetLocalExtAlgebra(g.wiresCoeff(i)))
	}

	accs := []gl.QuadraticExtensionAlgebraVariable{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		accs = append(accs, vars.GetLocalExtAlgebra(g.wiresAccs(i)))
	}

	constraints := []gl.QuadraticExtensionVariable{}
	acc := oldAcc
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeff := coeffs[i]
		tmp := glApi.MulExtensionAlgebra(acc, alpha)
		tmp = glApi.AddExtensionAlgebra(tmp, coeff)
		tmp = glApi.SubExtensionAlgebra(tmp, accs[i])
		for j := uint64(0); j < gl.D; j++ {
			constraints = append(constraints, tmp[j])
		}
		acc = accs[i]
	}

	return constraints
}
