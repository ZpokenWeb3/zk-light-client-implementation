package tests

import (
	"github.com/wormhole-foundation/example-near-light-client/types"
	"testing"
)

func TestReadCommonCircuitData(t *testing.T) {
	types.ReadCommonCircuitData("../testdata/test_circuit/common_circuit_data.json")
}
