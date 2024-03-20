package fri

import gl "github.com/wormhole-foundation/example-near-light-client/goldilocks"

type BatchInfo struct {
	Point       gl.QuadraticExtensionVariable
	Polynomials []PolynomialInfo
}

type InstanceInfo struct {
	Oracles []OracleInfo
	Batches []BatchInfo
}

type OpeningBatch struct {
	Values []gl.QuadraticExtensionVariable
}

type Openings struct {
	Batches []OpeningBatch
}
