package fri

import (
	"math"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
)

type PolynomialInfo struct {
	OracleIndex    uint64
	PolynomialInfo uint64
}

type OracleInfo struct {
	NumPolys uint64
	Blinding bool
}

type PlonkOracle struct {
	index    uint64
	blinding bool
}

var CONSTANTS_SIGMAS = PlonkOracle{
	index:    0,
	blinding: false,
}

var WIRES = PlonkOracle{
	index:    1,
	blinding: true,
}

var ZS_PARTIAL_PRODUCTS = PlonkOracle{
	index:    2,
	blinding: true,
}

var QUOTIENT = PlonkOracle{
	index:    3,
	blinding: true,
}

func polynomialInfoFromRange(c *types.CommonCircuitData, oracleIdx uint64, startPolyIdx uint64, endPolyIdx uint64) []PolynomialInfo {
	returnArr := make([]PolynomialInfo, 0)
	for i := startPolyIdx; i < endPolyIdx; i++ {
		returnArr = append(returnArr,
			PolynomialInfo{
				OracleIndex:    oracleIdx,
				PolynomialInfo: i,
			})
	}

	return returnArr
}

// Range of the sigma polynomials in the `constants_sigmas_commitment`.
func sigmasRange(c *types.CommonCircuitData) []uint64 {
	returnArr := make([]uint64, 0)
	for i := c.NumConstants; i <= c.NumConstants+c.Config.NumRoutedWires; i++ {
		returnArr = append(returnArr, i)
	}

	return returnArr
}

func numPreprocessedPolys(c *types.CommonCircuitData) uint64 {
	sigmasRange := sigmasRange(c)
	return sigmasRange[len(sigmasRange)-1]
}

func numZSPartialProductsPolys(c *types.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * (1 + c.NumPartialProducts)
}

func numQuotientPolys(c *types.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * c.QuotientDegreeFactor
}

func friPreprocessedPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		CONSTANTS_SIGMAS.index,
		0,
		numPreprocessedPolys(c),
	)
}

func friWirePolys(c *types.CommonCircuitData) []PolynomialInfo {
	numWirePolys := c.Config.NumWires
	return polynomialInfoFromRange(c, WIRES.index, 0, numWirePolys)
}

func friZSPartialProductsPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		ZS_PARTIAL_PRODUCTS.index,
		0,
		numZSPartialProductsPolys(c),
	)
}

func friQuotientPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		QUOTIENT.index,
		0,
		numQuotientPolys(c),
	)
}

func friZSPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		ZS_PARTIAL_PRODUCTS.index,
		0,
		c.Config.NumChallenges,
	)
}

func friOracles(c *types.CommonCircuitData) []OracleInfo {
	return []OracleInfo{
		{
			NumPolys: numPreprocessedPolys(c),
			Blinding: CONSTANTS_SIGMAS.blinding,
		},
		{
			NumPolys: c.Config.NumWires,
			Blinding: WIRES.blinding,
		},
		{
			NumPolys: numZSPartialProductsPolys(c),
			Blinding: ZS_PARTIAL_PRODUCTS.blinding,
		},
		{
			NumPolys: numQuotientPolys(c),
			Blinding: QUOTIENT.blinding,
		},
	}
}

func friAllPolys(c *types.CommonCircuitData) []PolynomialInfo {
	returnArr := make([]PolynomialInfo, 0)
	returnArr = append(returnArr, friPreprocessedPolys(c)...)
	returnArr = append(returnArr, friWirePolys(c)...)
	returnArr = append(returnArr, friZSPartialProductsPolys(c)...)
	returnArr = append(returnArr, friQuotientPolys(c)...)

	return returnArr
}

// This does not add any constraints, it's just a sanity check on the friParams
// It's a 1-1 port of assert_noncanonical_indices_ok from fri::recursive_verifier in plonky2
func assertNoncanonicalIndicesOK(friParams types.FriParams) {
	numAmbiguousElems := uint64(math.MaxUint64) - goldilocks.Modulus().Uint64() + 1
	queryError := friParams.Config.Rate()
	pAmbiguous := float64(numAmbiguousElems) / float64(goldilocks.Modulus().Uint64())
	if pAmbiguous >= queryError*1e-5 {
		panic("A non-negligible portion of field elements are in the range that permits non-canonical encodings. Need to do more analysis or enforce canonical encodings.")
	}
}

// This does not add any constraints, it is just a sanity check on the shapes of the proof variable
// and given FriParams. It's a 1-1 port of validate_fri_proof_shape from fri::validate_shape in plonky2
func validateFriProofShape(proof *variables.FriProof, instance InstanceInfo, params *types.FriParams) {
	const SALT_SIZE = 4

	commitPhaseMerkleCaps := proof.CommitPhaseMerkleCaps
	queryRoundProofs := proof.QueryRoundProofs
	finalPoly := proof.FinalPoly

	capHeight := params.Config.CapHeight
	for _, cap := range commitPhaseMerkleCaps {
		if 1<<capHeight != len(cap) {
			panic("config cap_height does not match commit_phase_merkle_caps")
		}
	}

	for _, queryRound := range queryRoundProofs {
		initialTreesProof := queryRound.InitialTreesProof
		steps := queryRound.Steps
		if len(initialTreesProof.EvalsProofs) != len(instance.Oracles) {
			panic("eval proofs length is not equal to instance oracles length")
		}
		for i, evalProof := range initialTreesProof.EvalsProofs {
			leaf := evalProof.Elements
			merkleProof := evalProof.MerkleProof
			oracle := instance.Oracles[i]
			salt_size := 0
			if oracle.Blinding && params.Hiding {
				salt_size = SALT_SIZE
			}
			if len(leaf) != (int(oracle.NumPolys) + salt_size) {
				panic("eval proof leaf length doesn't match oracle info")
			}
			if len(merkleProof.Siblings)+int(capHeight) != params.LdeBits() {
				panic("length of merkle proof + capHeight doesn't match lde_bits from params")
			}
		}
		if len(steps) != len(params.ReductionArityBits) {
			panic("length of steps != params.reduction_arity_bits")
		}

		codewordLenBits := params.LdeBits()
		for i, step := range steps {
			evals := step.Evals
			merkleProof := step.MerkleProof
			arityBits := params.ReductionArityBits[i]

			arity := 1 << arityBits
			codewordLenBits -= int(arityBits)

			if len(evals) != arity {
				panic("len evals doesn't match arity")
			}

			if len(merkleProof.Siblings)+int(capHeight) != codewordLenBits {
				panic("len merkleProof doesn't match codewordLenBits")
			}
		}
	}

	if len(finalPoly.Coeffs) != params.FinalPolyLen() {
		panic("len finalPoly doesn't match params FinalPolyLen")
	}
}
