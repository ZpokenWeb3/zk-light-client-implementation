package variables

import gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"

type OpeningSet struct {
	Constants       []gl.QuadraticExtensionVariable // Length = CommonCircuitData.Constants
	PlonkSigmas     []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumRoutedWires
	Wires           []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumWires
	PlonkZs         []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges
	PlonkZsNext     []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges
	PartialProducts []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges * CommonCircuitData.NumPartialProducts
	QuotientPolys   []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges * CommonCircuitData.QuotientDegreeFactor
}

type ProofChallenges struct {
	PlonkBetas    []gl.Variable
	PlonkGammas   []gl.Variable
	PlonkAlphas   []gl.Variable
	PlonkZeta     gl.QuadraticExtensionVariable
	FriChallenges FriChallenges
}
