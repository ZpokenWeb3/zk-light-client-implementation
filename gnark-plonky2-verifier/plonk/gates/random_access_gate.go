package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
)

var randomAccessGateRegex = regexp.MustCompile("RandomAccessGate { bits: (?P<bits>[0-9]+), num_copies: (?P<numCopies>[0-9]+), num_extra_constants: (?P<numExtraConstants>[0-9]+), _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=(?P<base>[0-9]+)>")

func deserializeRandomAccessGate(parameters map[string]string) Gate {
	// Has the format "RandomAccessGate { bits: 2, num_copies: 13, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"
	bits, hasBits := parameters["bits"]
	numCopies, hasNumCopies := parameters["numCopies"]
	numExtraConstants, hasNumExtraConstants := parameters["numExtraConstants"]

	if !hasBits || !hasNumCopies || !hasNumExtraConstants {
		panic("missing bits, numCopies, numExtraConstants or base in RandomAccessGate")
	}

	bitsInt, err := strconv.ParseUint(bits, 10, 64)
	if err != nil {
		panic("invalid bits in RandomAccessGate")
	}

	numCopiesInt, err := strconv.ParseUint(numCopies, 10, 64)
	if err != nil {
		panic("invalid numCopies in RandomAccessGate")
	}

	numExtraConstantsInt, err := strconv.ParseUint(numExtraConstants, 10, 64)
	if err != nil {
		panic("invalid numExtraConstants in RandomAccessGate")
	}

	base, hasBase := parameters["base"]
	if !hasBase {
		panic("Missing field base in RandomAccessGate")
	}

	baseInt, err := strconv.Atoi(base)
	if err != nil {
		panic("Invalid base field in RandomAccessGate")
	}

	if baseInt != gl.D {
		panic("Expected base field in RandomAccessGate to equal gl.D")
	}

	return NewRandomAccessGate(bitsInt, numCopiesInt, numExtraConstantsInt)
}

type RandomAccessGate struct {
	bits              uint64
	numCopies         uint64
	numExtraConstants uint64
}

func NewRandomAccessGate(bits uint64, numCopies uint64, numExtraConstants uint64) *RandomAccessGate {
	return &RandomAccessGate{
		bits:              bits,
		numCopies:         numCopies,
		numExtraConstants: numExtraConstants,
	}
}

func (g *RandomAccessGate) Id() string {
	return fmt.Sprintf("RandomAccessGate { bits: %d, num_copies: %d, num_extra_constants: %d }", g.bits, g.numCopies, g.numExtraConstants)
}

func (g *RandomAccessGate) vecSize() uint64 {
	return 1 << g.bits
}

func (g *RandomAccessGate) WireAccessIndex(copy uint64) uint64 {
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireAccessIndex called with copy >= num_copies")
	}
	return (2 + g.vecSize()) * copy
}

func (g *RandomAccessGate) WireClaimedElement(copy uint64) uint64 {
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireClaimedElement called with copy >= num_copies")
	}

	return (2+g.vecSize())*copy + 1
}

func (g *RandomAccessGate) WireListItem(i uint64, copy uint64) uint64 {
	if i >= g.vecSize() {
		panic("RandomAccessGate.WireListItem called with i >= vec_size")
	}
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireListItem called with copy >= num_copies")
	}

	return (2+g.vecSize())*copy + 2 + i
}

func (g *RandomAccessGate) startExtraConstants() uint64 {
	return (2 + g.vecSize()) * g.numCopies
}

func (g *RandomAccessGate) wireExtraConstant(i uint64) uint64 {
	if i >= g.numExtraConstants {
		panic("RandomAccessGate.wireExtraConstant called with i >= num_extra_constants")
	}

	return g.startExtraConstants() + i
}

func (g *RandomAccessGate) NumRoutedWires() uint64 {
	return g.startExtraConstants() + g.numExtraConstants
}

func (g *RandomAccessGate) WireBit(i uint64, copy uint64) uint64 {
	if i >= g.bits {
		panic("RandomAccessGate.WireBit called with i >= bits")
	}
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireBit called with copy >= num_copies")
	}

	return g.NumRoutedWires() + copy*g.bits + i
}

func (g *RandomAccessGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	two := gl.NewVariable(2).ToQuadraticExtension()
	constraints := []gl.QuadraticExtensionVariable{}

	for copy := uint64(0); copy < g.numCopies; copy++ {
		accessIndex := vars.localWires[g.WireAccessIndex(copy)]
		listItems := []gl.QuadraticExtensionVariable{}
		for i := uint64(0); i < g.vecSize(); i++ {
			listItems = append(listItems, vars.localWires[g.WireListItem(i, copy)])
		}
		claimedElement := vars.localWires[g.WireClaimedElement(copy)]
		bits := []gl.QuadraticExtensionVariable{}
		for i := uint64(0); i < g.bits; i++ {
			bits = append(bits, vars.localWires[g.WireBit(i, copy)])
		}

		// Assert that each bit wire value is indeed boolean.
		for _, b := range bits {
			bSquared := glApi.MulExtension(b, b)
			constraints = append(constraints, glApi.SubExtension(bSquared, b))
		}

		// Assert that the binary decomposition was correct.
		reconstructedIndex := glApi.ReduceWithPowers(bits, two)
		constraints = append(constraints, glApi.SubExtension(reconstructedIndex, accessIndex))

		for _, b := range bits {
			listItemsTmp := []gl.QuadraticExtensionVariable{}
			for i := 0; i < len(listItems); i += 2 {
				x := listItems[i]
				y := listItems[i+1]

				// This is computing `if b { x } else { y }`
				// i.e. `x + b(y - x)`.
				diff := glApi.SubExtension(y, x)
				mul := glApi.MulExtension(b, diff)
				add := glApi.AddExtension(x, mul)

				listItemsTmp = append(listItemsTmp, add)
			}
			listItems = listItemsTmp
		}

		if len(listItems) != 1 {
			panic("listItems(len) != 1")
		}

		constraints = append(constraints, glApi.SubExtension(listItems[0], claimedElement))
	}

	for i := uint64(0); i < g.numExtraConstants; i++ {
		constraints = append(constraints, glApi.SubExtension(vars.localConstants[i], vars.localWires[g.wireExtraConstant(i)]))
	}

	return constraints
}
