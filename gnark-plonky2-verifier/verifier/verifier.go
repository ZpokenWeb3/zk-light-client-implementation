package verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/wormhole-foundation/example-near-light-client/challenger"
	"github.com/wormhole-foundation/example-near-light-client/fri"
	gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"
	"github.com/wormhole-foundation/example-near-light-client/plonk"
	"github.com/wormhole-foundation/example-near-light-client/poseidon"
	"github.com/wormhole-foundation/example-near-light-client/types"
	"github.com/wormhole-foundation/example-near-light-client/variables"
)

type VerifierChip struct {
	api               frontend.API             `gnark:"-"`
	glChip            *gl.Chip                 `gnark:"-"`
	poseidonGlChip    *poseidon.GoldilocksChip `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip      `gnark:"-"`
	plonkChip         *plonk.PlonkChip         `gnark:"-"`
	friChip           *fri.Chip                `gnark:"-"`
	commonData        types.CommonCircuitData  `gnark:"-"`
}

func NewVerifierChip(api frontend.API, commonCircuitData types.CommonCircuitData) *VerifierChip {
	glChip := gl.New(api)
	friChip := fri.NewChip(api, &commonCircuitData, &commonCircuitData.FriParams)
	plonkChip := plonk.NewPlonkChip(api, commonCircuitData)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &VerifierChip{
		api:               api,
		glChip:            glChip,
		poseidonGlChip:    poseidonGlChip,
		poseidonBN254Chip: poseidonBN254Chip,
		plonkChip:         plonkChip,
		friChip:           friChip,
		commonData:        commonCircuitData,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []gl.Variable) poseidon.GoldilocksHashOut {
	return c.poseidonGlChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(
	proof variables.Proof,
	publicInputsHash poseidon.GoldilocksHashOut,
	verifierData variables.VerifierOnlyCircuitData,
) variables.ProofChallenges {
	config := c.commonData.Config
	numChallenges := config.NumChallenges
	challenger := challenger.NewChip(c.api)

	var circuitDigest = verifierData.CircuitDigest

	challenger.ObserveBN254Hash(circuitDigest)
	challenger.ObserveHash(publicInputsHash)
	challenger.ObserveCap(proof.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()

	challenger.ObserveOpenings(c.friChip.ToOpenings(proof.Openings))

	return variables.ProofChallenges{
		PlonkBetas:  plonkBetas,
		PlonkGammas: plonkGammas,
		PlonkAlphas: plonkAlphas,
		PlonkZeta:   plonkZeta,
		FriChallenges: challenger.GetFriChallenges(
			proof.OpeningProof.CommitPhaseMerkleCaps,
			proof.OpeningProof.FinalPoly,
			proof.OpeningProof.PowWitness,
			config.FriConfig,
		),
	}
}

func (c *VerifierChip) rangeCheckProof(proof variables.Proof) {
	// Need to verify the plonky2 proof's openings, openings proof (other than the sibling elements), fri's final poly, pow witness.

	// Note that this is NOT range checking the public inputs (first 32 elements should be no more than 8 bits and the last 4 elements should be no more than 64 bits).  Since this is currently being inputted via the smart contract,
	// we will assume that caller is doing that check.

	// Range check the proof's openings.
	for _, constant := range proof.Openings.Constants {
		c.glChip.RangeCheckQE(constant)
	}

	for _, plonkSigma := range proof.Openings.PlonkSigmas {
		c.glChip.RangeCheckQE(plonkSigma)
	}

	for _, wire := range proof.Openings.Wires {
		c.glChip.RangeCheckQE(wire)
	}

	for _, plonkZ := range proof.Openings.PlonkZs {
		c.glChip.RangeCheckQE(plonkZ)
	}

	for _, plonkZNext := range proof.Openings.PlonkZsNext {
		c.glChip.RangeCheckQE(plonkZNext)
	}

	for _, partialProduct := range proof.Openings.PartialProducts {
		c.glChip.RangeCheckQE(partialProduct)
	}

	for _, quotientPoly := range proof.Openings.QuotientPolys {
		c.glChip.RangeCheckQE(quotientPoly)
	}

	// Range check the openings proof.
	for _, queryRound := range proof.OpeningProof.QueryRoundProofs {
		for _, evalsProof := range queryRound.InitialTreesProof.EvalsProofs {
			for _, evalsProofElement := range evalsProof.Elements {
				c.glChip.RangeCheck(evalsProofElement)
			}
		}

		for _, queryStep := range queryRound.Steps {
			for _, eval := range queryStep.Evals {
				c.glChip.RangeCheckQE(eval)
			}
		}
	}

	// Range check the fri's final poly.
	for _, coeff := range proof.OpeningProof.FinalPoly.Coeffs {
		c.glChip.RangeCheckQE(coeff)
	}

	// Range check the pow witness.
	c.glChip.RangeCheck(proof.OpeningProof.PowWitness)
}

func (c *VerifierChip) Verify(
	proof variables.Proof,
	publicInputs []gl.Variable,
	verifierData variables.VerifierOnlyCircuitData,
) {
	c.rangeCheckProof(proof)

	// Generate the parts of the witness that is for the plonky2 proof input
	publicInputsHash := c.GetPublicInputsHash(publicInputs)
	proofChallenges := c.GetChallenges(proof, publicInputsHash, verifierData)

	c.plonkChip.Verify(proofChallenges, proof.Openings, publicInputsHash)

	initialMerkleCaps := []variables.FriMerkleCap{
		verifierData.ConstantSigmasCap,
		proof.WiresCap,
		proof.PlonkZsPartialProductsCap,
		proof.QuotientPolysCap,
	}

	c.friChip.VerifyFriProof(
		c.friChip.GetInstance(proofChallenges.PlonkZeta),
		c.friChip.ToOpenings(proof.Openings),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proof.OpeningProof,
	)
}
