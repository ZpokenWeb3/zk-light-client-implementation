package gates

import (
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/poseidon"
)

type EvaluationVars struct {
	localConstants   []gl.QuadraticExtensionVariable
	localWires       []gl.QuadraticExtensionVariable
	publicInputsHash poseidon.GoldilocksHashOut
}

func NewEvaluationVars(
	localConstants []gl.QuadraticExtensionVariable,
	localWires []gl.QuadraticExtensionVariable,
	publicInputsHash poseidon.GoldilocksHashOut,
) *EvaluationVars {
	return &EvaluationVars{
		localConstants:   localConstants,
		localWires:       localWires,
		publicInputsHash: publicInputsHash,
	}
}

func (e *EvaluationVars) RemovePrefix(numSelectors uint64) {
	e.localConstants = e.localConstants[numSelectors:]
}

func (e *EvaluationVars) GetLocalExtAlgebra(wireRange Range) gl.QuadraticExtensionAlgebraVariable {
	// For now, only support degree 2
	if wireRange.end-wireRange.start != gl.D {
		panic("Range must be of size D")
	}

	var ret gl.QuadraticExtensionAlgebraVariable
	for i := wireRange.start; i < wireRange.end; i++ {
		ret[i-wireRange.start] = e.localWires[i]
	}

	return ret
}
