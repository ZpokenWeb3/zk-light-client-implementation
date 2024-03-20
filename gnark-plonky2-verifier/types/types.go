package types

import (
	"github.com/wormhole-foundation/example-near-light-client/plonk/gates"
)

type FriConfig struct {
	RateBits        uint64
	CapHeight       uint64
	ProofOfWorkBits uint64
	NumQueryRounds  uint64
	// Note that we do not need `reduction_strategy` of type FriReductionStrategy as the plonky2 FriConfig has.
	// reduction_strategy is only used for computing `reduction_arity_bits`, which is serialized in the
	// CommonCircuitData.
}

func (fc *FriConfig) Rate() float64 {
	return 1.0 / float64((uint64(1) << fc.RateBits))
}

type FriParams struct {
	Config             FriConfig
	Hiding             bool
	DegreeBits         uint64
	ReductionArityBits []uint64
}

func (p *FriParams) TotalArities() int {
	res := 0
	for _, b := range p.ReductionArityBits {
		res += int(b)
	}
	return res
}

func (p *FriParams) MaxArityBits() int {
	res := 0
	for _, b := range p.ReductionArityBits {
		if int(b) > res {
			res = int(b)
		}
	}
	return res
}

func (p *FriParams) LdeBits() int {
	return int(p.DegreeBits + p.Config.RateBits)
}

func (p *FriParams) LdeSize() int {
	return 1 << p.LdeBits()
}

func (p *FriParams) FinalPolyBits() int {
	return int(p.DegreeBits) - p.TotalArities()
}

func (p *FriParams) FinalPolyLen() int {
	return int(1 << p.FinalPolyBits())
}

type CircuitConfig struct {
	NumWires                uint64
	NumRoutedWires          uint64
	NumConstants            uint64
	UseBaseArithmeticGate   bool
	SecurityBits            uint64
	NumChallenges           uint64
	ZeroKnowledge           bool
	MaxQuotientDegreeFactor uint64
	FriConfig               FriConfig
}

type CommonCircuitData struct {
	Config CircuitConfig
	FriParams
	GateIds              []string
	SelectorsInfo        gates.SelectorsInfo
	DegreeBits           uint64
	QuotientDegreeFactor uint64
	NumGateConstraints   uint64
	NumConstants         uint64
	NumPublicInputs      uint64
	KIs                  []uint64
	NumPartialProducts   uint64
}
