package gates

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

type EvaluateGatesChip struct {
	api frontend.API

	gates              []Gate
	numGateConstraints uint64

	selectorsInfo SelectorsInfo
}

func NewEvaluateGatesChip(
	api frontend.API,
	gates []Gate,
	numGateConstraints uint64,
	selectorsInfo SelectorsInfo,
) *EvaluateGatesChip {
	return &EvaluateGatesChip{
		api: api,

		gates:              gates,
		numGateConstraints: numGateConstraints,

		selectorsInfo: selectorsInfo,
	}
}

func (g *EvaluateGatesChip) computeFilter(
	row uint64,
	groupRange Range,
	s gl.QuadraticExtensionVariable,
	manySelector bool,
) gl.QuadraticExtensionVariable {
	glApi := gl.New(g.api)
	product := gl.OneExtension()
	for i := groupRange.start; i < groupRange.end; i++ {
		if i == uint64(row) {
			continue
		}
		tmp := gl.NewQuadraticExtensionVariable(gl.NewVariable(i), gl.Zero())
		product = glApi.MulExtension(product, glApi.SubExtension(tmp, s))
	}

	if manySelector {
		tmp := gl.NewQuadraticExtensionVariable(gl.NewVariable(UNUSED_SELECTOR), gl.Zero())
		product = glApi.MulExtension(product, glApi.SubExtension(tmp, s))
	}

	return product
}

func (g *EvaluateGatesChip) evalFiltered(
	gate Gate,
	vars EvaluationVars,
	row uint64,
	selectorIndex uint64,
	groupRange Range,
	numSelectors uint64,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(g.api)
	filter := g.computeFilter(row, groupRange, vars.localConstants[selectorIndex], numSelectors > 1)

	vars.RemovePrefix(numSelectors)

	unfiltered := gate.EvalUnfiltered(g.api, glApi, vars)
	for i := range unfiltered {
		unfiltered[i] = glApi.MulExtension(unfiltered[i], filter)
	}
	return unfiltered
}

func (g *EvaluateGatesChip) EvaluateGateConstraints(vars EvaluationVars) []gl.QuadraticExtensionVariable {
	glApi := gl.New(g.api)
	constraints := make([]gl.QuadraticExtensionVariable, g.numGateConstraints)
	for i := range constraints {
		constraints[i] = gl.ZeroExtension()
	}

	for i, gate := range g.gates {
		selectorIndex := g.selectorsInfo.selectorIndices[i]

		gateConstraints := g.evalFiltered(
			gate,
			vars,
			uint64(i),
			selectorIndex,
			g.selectorsInfo.groups[selectorIndex],
			g.selectorsInfo.NumSelectors(),
		)

		for i, constraint := range gateConstraints {
			if uint64(i) >= g.numGateConstraints {
				panic("num_constraints() gave too low of a number")
			}
			constraints[i] = glApi.AddExtension(constraints[i], constraint)
		}
	}

	return constraints
}
