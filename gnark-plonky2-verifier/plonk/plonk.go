package plonk

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/plonk/gates"
	"github.com/wormhole-foundation/example-near-light-client/poseidon"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
)

type PlonkChip struct {
	api frontend.API `gnark:"-"`

	commonData types.CommonCircuitData `gnark:"-"`

	// These are global constant variables that we use in this Chip that we save here.
	// This avoids having to recreate them every time we use them.
	DEGREE        gl.Variable                   `gnark:"-"`
	DEGREE_BITS_F gl.Variable                   `gnark:"-"`
	DEGREE_QE     gl.QuadraticExtensionVariable `gnark:"-"`
	commonDataKIs []gl.Variable                 `gnark:"-"`

	evaluateGatesChip *gates.EvaluateGatesChip
}

func NewPlonkChip(api frontend.API, commonData types.CommonCircuitData) *PlonkChip {
	// Create the gates based on commonData GateIds
	createdGates := []gates.Gate{}
	for _, gateId := range commonData.GateIds {
		createdGates = append(createdGates, gates.GateInstanceFromId(gateId))
	}

	evaluateGatesChip := gates.NewEvaluateGatesChip(
		api,
		createdGates,
		commonData.NumGateConstraints,
		commonData.SelectorsInfo,
	)

	return &PlonkChip{
		api: api,

		commonData: commonData,

		DEGREE:        gl.NewVariable(1 << commonData.DegreeBits),
		DEGREE_BITS_F: gl.NewVariable(commonData.DegreeBits),
		DEGREE_QE:     gl.NewVariable(1 << commonData.DegreeBits).ToQuadraticExtension(),
		commonDataKIs: gl.Uint64ArrayToVariableArray(commonData.KIs),

		evaluateGatesChip: evaluateGatesChip,
	}
}

func (p *PlonkChip) expPowerOf2Extension(x gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)
	for i := uint64(0); i < p.commonData.DegreeBits; i++ {
		x = glApi.MulExtension(x, x)
	}
	return x
}

func (p *PlonkChip) evalL0(x gl.QuadraticExtensionVariable, xPowN gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	// L_0(x) = (x^n - 1) / (n * (x - 1))
	glApi := gl.New(p.api)
	evalZeroPoly := glApi.SubExtension(
		xPowN,
		gl.OneExtension(),
	)
	denominator := glApi.SubExtension(
		glApi.ScalarMulExtension(x, p.DEGREE),
		p.DEGREE_QE,
	)

	quotient, hasQuotient := glApi.DivExtension(
		evalZeroPoly,
		denominator,
	)

	p.api.AssertIsEqual(hasQuotient, frontend.Variable(1))

	return quotient
}

func (p *PlonkChip) checkPartialProducts(
	numerators []gl.QuadraticExtensionVariable,
	denominators []gl.QuadraticExtensionVariable,
	challengeNum uint64,
	openings variables.OpeningSet,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)
	numPartProds := p.commonData.NumPartialProducts
	quotDegreeFactor := p.commonData.QuotientDegreeFactor

	productAccs := make([]gl.QuadraticExtensionVariable, 0, numPartProds+2)
	productAccs = append(productAccs, openings.PlonkZs[challengeNum])
	productAccs = append(productAccs, openings.PartialProducts[challengeNum*numPartProds:(challengeNum+1)*numPartProds]...)
	productAccs = append(productAccs, openings.PlonkZsNext[challengeNum])

	partialProductChecks := make([]gl.QuadraticExtensionVariable, 0, numPartProds)

	for i := uint64(0); i <= numPartProds; i += 1 {
		ppStartIdx := i * quotDegreeFactor
		numeProduct := numerators[ppStartIdx]
		denoProduct := denominators[ppStartIdx]
		for j := uint64(1); j < quotDegreeFactor; j++ {
			numeProduct = glApi.MulExtension(numeProduct, numerators[ppStartIdx+j])
			denoProduct = glApi.MulExtension(denoProduct, denominators[ppStartIdx+j])
		}

		partialProductCheck := glApi.SubExtension(
			glApi.MulExtension(productAccs[i], numeProduct),
			glApi.MulExtension(productAccs[i+1], denoProduct),
		)

		partialProductChecks = append(partialProductChecks, partialProductCheck)
	}
	return partialProductChecks
}

func (p *PlonkChip) evalVanishingPoly(
	vars gates.EvaluationVars,
	proofChallenges variables.ProofChallenges,
	openings variables.OpeningSet,
	zetaPowN gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)
	constraintTerms := p.evaluateGatesChip.EvaluateGateConstraints(vars)

	// Calculate the k[i] * x
	sIDs := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		sIDs[i] = glApi.ScalarMulExtension(proofChallenges.PlonkZeta, p.commonDataKIs[i])
	}

	// Calculate L_0(zeta)
	l0Zeta := p.evalL0(proofChallenges.PlonkZeta, zetaPowN)

	vanishingZ1Terms := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumChallenges)
	vanishingPartialProductsTerms := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := glApi.MulExtension(
			l0Zeta,
			glApi.SubExtension(openings.PlonkZs[i], gl.OneExtension()))
		vanishingZ1Terms = append(vanishingZ1Terms, z1_term)

		numeratorValues := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumRoutedWires)
		denominatorValues := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumRoutedWires)
		for j := uint64(0); j < p.commonData.Config.NumRoutedWires; j++ {
			// The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
			// `beta * s_sigma + wire_value + gamma`.
			wireValuePlusGamma := glApi.AddExtension(
				openings.Wires[j],
				gl.NewQuadraticExtensionVariable(proofChallenges.PlonkGammas[i], gl.Zero()),
			)

			numerator := glApi.AddExtension(
				glApi.MulExtension(
					gl.NewQuadraticExtensionVariable(proofChallenges.PlonkBetas[i], gl.Zero()),
					sIDs[j],
				),
				wireValuePlusGamma,
			)

			denominator := glApi.AddExtension(
				glApi.MulExtension(
					gl.NewQuadraticExtensionVariable(proofChallenges.PlonkBetas[i], gl.Zero()),
					openings.PlonkSigmas[j],
				),
				wireValuePlusGamma,
			)

			numeratorValues = append(numeratorValues, numerator)
			denominatorValues = append(denominatorValues, denominator)
		}

		vanishingPartialProductsTerms = append(
			vanishingPartialProductsTerms,
			p.checkPartialProducts(numeratorValues, denominatorValues, i, openings)...,
		)
	}

	vanishingTerms := append(vanishingZ1Terms, vanishingPartialProductsTerms...)
	vanishingTerms = append(vanishingTerms, constraintTerms...)

	reducedValues := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		reducedValues[i] = gl.ZeroExtension()
	}

	// reverse iterate the vanishingPartialProductsTerms array
	for i := len(vanishingTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			reducedValues[j] = glApi.AddExtension(
				vanishingTerms[i],
				glApi.ScalarMulExtension(
					reducedValues[j],
					proofChallenges.PlonkAlphas[j],
				),
			)
		}
	}

	return reducedValues
}

func (p *PlonkChip) Verify(
	proofChallenges variables.ProofChallenges,
	openings variables.OpeningSet,
	publicInputsHash poseidon.GoldilocksHashOut,
) {
	glApi := gl.New(p.api)

	// Calculate zeta^n
	zetaPowN := p.expPowerOf2Extension(proofChallenges.PlonkZeta)

	localConstants := openings.Constants
	localWires := openings.Wires
	vars := gates.NewEvaluationVars(
		localConstants,
		localWires,
		publicInputsHash,
	)

	vanishingPolysZeta := p.evalVanishingPoly(*vars, proofChallenges, openings, zetaPowN)

	// Calculate Z(H)
	zHZeta := glApi.SubExtension(zetaPowN, gl.OneExtension())

	// `quotient_polys_zeta` holds `num_challenges * quotient_degree_factor` evaluations.
	// Each chunk of `quotient_degree_factor` holds the evaluations of `t_0(zeta),...,t_{quotient_degree_factor-1}(zeta)`
	// where the "real" quotient polynomial is `t(X) = t_0(X) + t_1(X)*X^n + t_2(X)*X^{2n} + ...`.
	// So to reconstruct `t(zeta)` we can compute `reduce_with_powers(chunk, zeta^n)` for each
	// `quotient_degree_factor`-sized chunk of the original evaluations.
	for i := 0; i < len(vanishingPolysZeta); i++ {
		quotientPolysStartIdx := i * int(p.commonData.QuotientDegreeFactor)
		quotientPolysEndIdx := quotientPolysStartIdx + int(p.commonData.QuotientDegreeFactor)
		prod := glApi.MulExtension(
			zHZeta,
			glApi.ReduceWithPowers(
				openings.QuotientPolys[quotientPolysStartIdx:quotientPolysEndIdx],
				zetaPowN,
			),
		)

		glApi.AssertIsEqualExtension(vanishingPolysZeta[i], prod)
	}
}
