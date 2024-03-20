package gates

import (
	"regexp"

	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/consensys/gnark/frontend"
)

var noopGateRegex = regexp.MustCompile("NoopGate")

func deserializeNoopGate(parameters map[string]string) Gate {
	// Has the format "NoopGate"
	return NewNoopGate()
}

type NoopGate struct {
}

func NewNoopGate() *NoopGate {
	return &NoopGate{}
}

func (g *NoopGate) Id() string {
	return "NoopGate"
}

func (g *NoopGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	return []gl.QuadraticExtensionVariable{}
}
