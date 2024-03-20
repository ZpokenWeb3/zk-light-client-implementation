package poseidon

// This is a customized implementation of the Poseidon hash function inside the BN254 field.
// This implementation is based on the following implementation:
//
// 		https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon.go
//
// The input and output are modified to ingest Goldilocks field elements.

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

const BN254_FULL_ROUNDS int = 8
const BN254_PARTIAL_ROUNDS int = 56
const BN254_SPONGE_WIDTH int = 4
const BN254_SPONGE_RATE int = 3

type BN254Chip struct {
	api frontend.API `gnark:"-"`
	gl  *gl.Chip     `gnark:"-"`
}

type BN254State = [BN254_SPONGE_WIDTH]frontend.Variable
type BN254HashOut = frontend.Variable

func NewBN254Chip(api frontend.API) *BN254Chip {
	if api.Compiler().Field().Cmp(bn254.ID.ScalarField()) != 0 {
		panic("Gnark compiler not set to BN254 scalar field")
	}

	return &BN254Chip{api: api, gl: gl.New(api)}
}

func (c *BN254Chip) Poseidon(state BN254State) BN254State {
	state = c.ark(state, 0)
	state = c.fullRounds(state, true)
	state = c.partialRounds(state)
	state = c.fullRounds(state, false)
	return state
}

func (c *BN254Chip) HashNoPad(input []gl.Variable) BN254HashOut {
	state := BN254State{
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
	}

	two_to_32 := new(big.Int).SetInt64(1 << 32)
	two_to_64 := new(big.Int).Mul(two_to_32, two_to_32)

	for i := 0; i < len(input); i += BN254_SPONGE_RATE * 3 {
		endI := c.min(len(input), i+BN254_SPONGE_RATE*3)
		rateChunk := input[i:endI]
		for j, stateIdx := 0, 0; j < len(rateChunk); j, stateIdx = j+3, stateIdx+1 {
			endJ := c.min(len(rateChunk), j+3)
			bn254Chunk := rateChunk[j:endJ]

			inter := frontend.Variable(0)
			for k := 0; k < len(bn254Chunk); k++ {
				inter = c.api.MulAcc(inter, bn254Chunk[k].Limb, new(big.Int).Exp(two_to_64, big.NewInt(int64(k)), nil))
			}

			state[stateIdx+1] = inter
		}

		state = c.Poseidon(state)
	}

	return BN254HashOut(state[0])
}

func (c *BN254Chip) HashOrNoop(input []gl.Variable) BN254HashOut {
	if len(input) <= 3 {
		returnVal := frontend.Variable(0)

		alpha := new(big.Int).SetInt64(1 << 32)
		alpha = new(big.Int).Mul(alpha, alpha)
		for i, inputElement := range input {
			mulFactor := new(big.Int).Exp(alpha, big.NewInt(int64(i)), nil)
			returnVal = c.api.MulAcc(returnVal, inputElement.Limb, mulFactor)
		}

		return BN254HashOut(returnVal)
	} else {
		return c.HashNoPad(input)
	}
}

func (c *BN254Chip) TwoToOne(left BN254HashOut, right BN254HashOut) BN254HashOut {
	var inputs BN254State
	inputs[0] = frontend.Variable(0)
	inputs[1] = frontend.Variable(0)
	inputs[2] = left
	inputs[3] = right
	state := c.Poseidon(inputs)
	return state[0]
}

func (c *BN254Chip) ToVec(hash BN254HashOut) []gl.Variable {
	bits := c.api.ToBinary(hash)

	returnElements := []gl.Variable{}

	// Split into 7 byte chunks, since 8 byte chunks can result in collisions
	chunkSize := 56
	for i := 0; i < len(bits); i += chunkSize {
		maxIdx := c.min(len(bits), i+chunkSize)
		bitChunk := bits[i:maxIdx]
		returnElements = append(returnElements, gl.NewVariable(c.api.FromBinary(bitChunk...)))
	}

	return returnElements
}

func (c *BN254Chip) min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

func (c *BN254Chip) fullRounds(state BN254State, isFirst bool) BN254State {
	for i := 0; i < BN254_FULL_ROUNDS/2-1; i++ {
		state = c.exp5state(state)
		if isFirst {
			state = c.ark(state, (i+1)*BN254_SPONGE_WIDTH)
		} else {
			state = c.ark(state, (BN254_FULL_ROUNDS/2+1)*BN254_SPONGE_WIDTH+BN254_PARTIAL_ROUNDS+i*BN254_SPONGE_WIDTH)
		}
		state = c.mix(state, mMatrix)
	}

	state = c.exp5state(state)
	if isFirst {
		state = c.ark(state, (BN254_FULL_ROUNDS/2)*BN254_SPONGE_WIDTH)
		state = c.mix(state, pMatrix)
	} else {
		state = c.mix(state, mMatrix)
	}

	return state
}

func (c *BN254Chip) partialRounds(state BN254State) BN254State {
	for i := 0; i < BN254_PARTIAL_ROUNDS; i++ {
		state[0] = c.exp5(state[0])
		state[0] = c.api.Add(state[0], cConstants[(BN254_FULL_ROUNDS/2+1)*BN254_SPONGE_WIDTH+i])

		newState0 := frontend.Variable(0)
		for j := 0; j < BN254_SPONGE_WIDTH; j++ {
			newState0 = c.api.MulAcc(newState0, sConstants[(BN254_SPONGE_WIDTH*2-1)*i+j], state[j])
		}

		for k := 1; k < BN254_SPONGE_WIDTH; k++ {
			state[k] = c.api.MulAcc(state[k], state[0], sConstants[(BN254_SPONGE_WIDTH*2-1)*i+BN254_SPONGE_WIDTH+k-1])
		}
		state[0] = newState0
	}

	return state
}

func (c *BN254Chip) ark(state BN254State, it int) BN254State {
	var result BN254State

	for i := 0; i < len(state); i++ {
		result[i] = c.api.Add(state[i], cConstants[it+i])
	}

	return result
}

func (c *BN254Chip) exp5(x frontend.Variable) frontend.Variable {
	x2 := c.api.Mul(x, x)
	x4 := c.api.Mul(x2, x2)
	return c.api.Mul(x4, x)
}

func (c *BN254Chip) exp5state(state BN254State) BN254State {
	for i := 0; i < BN254_SPONGE_WIDTH; i++ {
		state[i] = c.exp5(state[i])
	}
	return state
}

func (c *BN254Chip) mix(state_ BN254State, constantMatrix [][]*big.Int) BN254State {
	var result BN254State

	for i := 0; i < BN254_SPONGE_WIDTH; i++ {
		result[i] = frontend.Variable(0)
	}

	for i := 0; i < BN254_SPONGE_WIDTH; i++ {
		for j := 0; j < BN254_SPONGE_WIDTH; j++ {
			result[i] = c.api.MulAcc(result[i], constantMatrix[j][i], state_[j])
		}
	}

	return result
}
