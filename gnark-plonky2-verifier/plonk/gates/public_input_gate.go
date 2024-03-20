package gates

import (
	"regexp"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var publicInputGateRegex = regexp.MustCompile("PublicInputGate")

func deserializePublicInputGate(parameters map[string]string) Gate {
	// Has the format "PublicInputGate"
	return NewPublicInputGate()
}

type PublicInputGate struct {
}

func NewPublicInputGate() *PublicInputGate {
	return &PublicInputGate{}
}

func (g *PublicInputGate) Id() string {
	return "PublicInputGate"
}

func (g *PublicInputGate) WiresPublicInputsHash() []uint64 {
	return []uint64{0, 1, 2, 3}
}

func (g *PublicInputGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	constraints := []gl.QuadraticExtensionVariable{}

	wires := g.WiresPublicInputsHash()
	hash_parts := vars.publicInputsHash
	for i := 0; i < len(wires); i++ {
		wire := wires[i]
		hash_part := hash_parts[i]

		tmp := gl.NewQuadraticExtensionVariable(hash_part, gl.Zero())
		diff := glApi.SubExtension(vars.localWires[wire], tmp)
		constraints = append(constraints, diff)
	}

	return constraints
}
