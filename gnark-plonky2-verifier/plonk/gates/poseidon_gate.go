package gates

import (
	"regexp"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/poseidon"
)

var poseidonGateRegex = regexp.MustCompile("PoseidonGate.*")

func deserializePoseidonGate(parameters map[string]string) Gate {
	// Has the format "PoseidonGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>"
	return NewPoseidonGate()
}

type PoseidonGate struct {
}

func NewPoseidonGate() *PoseidonGate {
	return &PoseidonGate{}
}

func (g *PoseidonGate) Id() string {
	return "PoseidonGate"
}

func (g *PoseidonGate) WireInput(i uint64) uint64 {
	return i
}

func (g *PoseidonGate) WireOutput(i uint64) uint64 {
	return poseidon.SPONGE_WIDTH + i
}

func (g *PoseidonGate) WireSwap() uint64 {
	return 2 * poseidon.SPONGE_WIDTH
}

const START_DELTA = 2*poseidon.SPONGE_WIDTH + 1

func (g *PoseidonGate) WireDelta(i uint64) uint64 {
	if i >= 4 {
		panic("Delta index out of range")
	}
	return START_DELTA + i
}

const START_FULL_0 = START_DELTA + 4

func (g *PoseidonGate) WireFullSBox0(round uint64, i uint64) uint64 {
	if round == 0 {
		panic("First-round S-box inputs are not stored as wires")
	}
	if round >= poseidon.HALF_N_FULL_ROUNDS {
		panic("S-box input round out of range")
	}
	if i >= poseidon.SPONGE_WIDTH {
		panic("S-box input index out of range")
	}

	return START_FULL_0 + (round-1)*poseidon.SPONGE_WIDTH + i
}

const START_PARTIAL = START_FULL_0 + (poseidon.HALF_N_FULL_ROUNDS-1)*poseidon.SPONGE_WIDTH

func (g *PoseidonGate) WirePartialSBox(round uint64) uint64 {
	if round >= poseidon.N_PARTIAL_ROUNDS {
		panic("S-box input round out of range")
	}
	return START_PARTIAL + round
}

const START_FULL_1 = START_PARTIAL + poseidon.N_PARTIAL_ROUNDS

func (g *PoseidonGate) WireFullSBox1(round uint64, i uint64) uint64 {
	if round >= poseidon.HALF_N_FULL_ROUNDS {
		panic("S-box input round out of range")
	}
	if i >= poseidon.SPONGE_WIDTH {
		panic("S-box input index out of range")
	}

	return START_FULL_1 + round*poseidon.SPONGE_WIDTH + i
}

func (g *PoseidonGate) WiresEnd() uint64 {
	return START_FULL_1 + poseidon.HALF_N_FULL_ROUNDS*poseidon.SPONGE_WIDTH
}

func (g *PoseidonGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	constraints := []gl.QuadraticExtensionVariable{}

	poseidonChip := poseidon.NewGoldilocksChip(api)

	// Assert that `swap` is binary.
	swap := vars.localWires[g.WireSwap()]
	swapMinusOne := glApi.SubExtension(swap, gl.OneExtension())
	constraints = append(constraints, glApi.MulExtension(swap, swapMinusOne))

	// Assert that each delta wire is set properly: `delta_i = swap * (rhs - lhs)`.
	for i := uint64(0); i < 4; i++ {
		inputLhs := vars.localWires[g.WireInput(i)]
		inputRhs := vars.localWires[g.WireInput(i+4)]
		deltaI := vars.localWires[g.WireDelta(i)]
		diff := glApi.SubExtension(inputRhs, inputLhs)
		expectedDeltaI := glApi.MulExtension(swap, diff)
		constraints = append(constraints, glApi.SubExtension(expectedDeltaI, deltaI))
	}

	// Compute the possibly-swapped input layer.
	var state [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionVariable
	for i := uint64(0); i < 4; i++ {
		deltaI := vars.localWires[g.WireDelta(i)]
		inputLhs := vars.localWires[g.WireInput(i)]
		inputRhs := vars.localWires[g.WireInput(i+4)]
		state[i] = glApi.AddExtension(inputLhs, deltaI)
		state[i+4] = glApi.SubExtension(inputRhs, deltaI)
	}
	for i := uint64(8); i < poseidon.SPONGE_WIDTH; i++ {
		state[i] = vars.localWires[g.WireInput(i)]
	}

	roundCounter := 0

	// First set of full rounds.
	for r := uint64(0); r < poseidon.HALF_N_FULL_ROUNDS; r++ {
		state = poseidonChip.ConstantLayerExtension(state, &roundCounter)
		if r != 0 {
			for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
				sBoxIn := vars.localWires[g.WireFullSBox0(r, i)]
				constraints = append(constraints, glApi.SubExtension(state[i], sBoxIn))
				state[i] = sBoxIn
			}
		}
		state = poseidonChip.SBoxLayerExtension(state)
		state = poseidonChip.MdsLayerExtension(state)
		roundCounter++
	}

	// Partial rounds.
	state = poseidonChip.PartialFirstConstantLayerExtension(state)
	state = poseidonChip.MdsPartialLayerInitExtension(state)

	for r := uint64(0); r < poseidon.N_PARTIAL_ROUNDS-1; r++ {
		sBoxIn := vars.localWires[g.WirePartialSBox(r)]
		constraints = append(constraints, glApi.SubExtension(state[0], sBoxIn))
		state[0] = poseidonChip.SBoxMonomialExtension(sBoxIn)
		state[0] = glApi.AddExtension(state[0], gl.NewQuadraticExtensionVariable(gl.NewVariable(poseidon.FAST_PARTIAL_ROUND_CONSTANTS[r]), gl.Zero()))
		state = poseidonChip.MdsPartialLayerFastExtension(state, int(r))
	}
	sBoxIn := vars.localWires[g.WirePartialSBox(poseidon.N_PARTIAL_ROUNDS-1)]
	constraints = append(constraints, glApi.SubExtension(state[0], sBoxIn))
	state[0] = poseidonChip.SBoxMonomialExtension(sBoxIn)
	state = poseidonChip.MdsPartialLayerFastExtension(state, poseidon.N_PARTIAL_ROUNDS-1)
	roundCounter += poseidon.N_PARTIAL_ROUNDS

	// Second set of full rounds.
	for r := uint64(0); r < poseidon.HALF_N_FULL_ROUNDS; r++ {
		state = poseidonChip.ConstantLayerExtension(state, &roundCounter)
		for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
			sBoxIn := vars.localWires[g.WireFullSBox1(r, i)]
			constraints = append(constraints, glApi.SubExtension(state[i], sBoxIn))
			state[i] = sBoxIn
		}
		state = poseidonChip.SBoxLayerExtension(state)
		state = poseidonChip.MdsLayerExtension(state)
		roundCounter++
	}

	for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
		constraints = append(constraints, glApi.SubExtension(state[i], vars.localWires[g.WireOutput(i)]))
	}

	return constraints
}
