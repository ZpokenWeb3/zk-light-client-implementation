package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var exponentiationGateRegex = regexp.MustCompile("ExponentiationGate { num_power_bits: (?P<numPowerBits>[0-9]+), _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=(?P<base>[0-9]+)>")

func deserializeExponentiationGate(parameters map[string]string) Gate {
	// Has the format "ExponentiationGate { num_power_bits: 67, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"
	numPowerBits, hasNumPowerBits := parameters["numPowerBits"]
	if !hasNumPowerBits {
		panic("Missing field num_power_bits in ExponentiationGate")
	}

	numPowerBitsInt, err := strconv.Atoi(numPowerBits)
	if err != nil {
		panic("Invalid num_power_bits field in ExponentiationGate")
	}

	base, hasBase := parameters["base"]
	if !hasBase {
		panic("Missing field base in ExponentiationGate")
	}

	baseInt, err := strconv.Atoi(base)
	if err != nil {
		panic("Invalid base field in ExponentiationGate")
	}

	if baseInt != gl.D {
		panic("Expected base field in ExponentiationGate to equal gl.D")
	}

	return NewExponentiationGate(uint64(numPowerBitsInt))
}

type ExponentiationGate struct {
	numPowerBits uint64
}

func NewExponentiationGate(numPowerBits uint64) *ExponentiationGate {
	return &ExponentiationGate{
		numPowerBits: numPowerBits,
	}
}

func (g *ExponentiationGate) Id() string {
	return fmt.Sprintf("ExponentiationGate { num_power_bits: %d }", g.numPowerBits)
}

func (g *ExponentiationGate) wireBase() uint64 {
	return 0
}

// / The `i`th bit of the exponent, in little-endian order.
func (g *ExponentiationGate) wirePowerBit(i uint64) uint64 {
	if i >= g.numPowerBits {
		panic("Invalid power bit index")
	}
	return 1 + i
}

func (g *ExponentiationGate) wireOutput() uint64 {
	return 1 + g.numPowerBits
}

func (g *ExponentiationGate) wireIntermediateValue(i uint64) uint64 {
	if i >= g.numPowerBits {
		panic("Invalid intermediate value index")
	}
	return 2 + g.numPowerBits + i
}

func (g *ExponentiationGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	base := vars.localWires[g.wireBase()]

	var powerBits []gl.QuadraticExtensionVariable
	for i := uint64(0); i < g.numPowerBits; i++ {
		powerBits = append(powerBits, vars.localWires[g.wirePowerBit(i)])
	}

	var intermediateValues []gl.QuadraticExtensionVariable
	for i := uint64(0); i < g.numPowerBits; i++ {
		intermediateValues = append(intermediateValues, vars.localWires[g.wireIntermediateValue(i)])
	}

	output := vars.localWires[g.wireOutput()]

	var constraints []gl.QuadraticExtensionVariable

	for i := uint64(0); i < g.numPowerBits; i++ {
		var prevIntermediateValue gl.QuadraticExtensionVariable
		if i == 0 {
			prevIntermediateValue = gl.OneExtension()
		} else {
			prevIntermediateValue = glApi.MulExtension(intermediateValues[i-1], intermediateValues[i-1])
		}

		// powerBits is in LE order, but we accumulate in BE order.
		curBit := powerBits[g.numPowerBits-i-1]

		// Do a polynomial representation of generaized select (where the selector variable doesn't have to be binary)
		// if b { x } else { y }
		// i.e. `bx - (by-y)`.
		tmp := glApi.MulExtension(curBit, gl.OneExtension())
		tmp = glApi.SubExtension(tmp, gl.OneExtension())
		mulBy := glApi.MulExtension(curBit, base)
		mulBy = glApi.SubExtension(mulBy, tmp)
		intermediateValueDiff := glApi.MulExtension(prevIntermediateValue, mulBy)
		intermediateValueDiff = glApi.SubExtension(intermediateValueDiff, intermediateValues[i])
		constraints = append(constraints, intermediateValueDiff)
	}

	outputDiff := glApi.SubExtension(output, intermediateValues[g.numPowerBits-1])
	constraints = append(constraints, outputDiff)

	return constraints
}
