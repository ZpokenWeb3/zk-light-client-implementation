package gates

import (
	"fmt"
	"regexp"

	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type Gate interface {
	Id() string
	EvalUnfiltered(
		api frontend.API,
		glApi *gl.Chip,
		vars EvaluationVars,
	) []gl.QuadraticExtensionVariable
}

var gateRegexHandlers = map[*regexp.Regexp]func(parameters map[string]string) Gate{
	arithmeticGateRegex:          deserializeArithmeticGate,
	arithmeticExtensionGateRegex: deserializeExtensionArithmeticGate,
	baseSumGateRegex:             deserializeBaseSumGate,
	constantGateRegex:            deserializeConstantGate,
	cosetInterpolationGateRegex:  deserializeCosetInterpolationGate,
	exponentiationGateRegex:      deserializeExponentiationGate,
	mulExtensionGateRegex:        deserializeMulExtensionGate,
	noopGateRegex:                deserializeNoopGate,
	poseidonGateRegex:            deserializePoseidonGate,
	poseidonMdsGateRegex:         deserializePoseidonMdsGate,
	publicInputGateRegex:         deserializePublicInputGate,
	randomAccessGateRegex:        deserializeRandomAccessGate,
	reducingExtensionGateRegex:   deserializeReducingExtensionGate,
	reducingGateRegex:            deserializeReducingGate,
}

func GateInstanceFromId(gateId string) Gate {
	for regex, handler := range gateRegexHandlers {
		matches := regex.FindStringSubmatch(gateId)
		if matches != nil {
			parameters := make(map[string]string)
			for i, name := range regex.SubexpNames() {
				if i != 0 && name != "" {
					parameters[name] = matches[i]
				}
			}

			if matches != nil {
				return handler(parameters)
			}
		}
	}
	panic(fmt.Sprintf("Unknown gate ID %s", gateId))
}
