package goldilocks

import (
	"math"

	"github.com/consensys/gnark/frontend"
)

// The types, structs, and functions in this file were ported over from the gnark library
// https://github.com/Consensys/gnark/blob/3421eaa7d544286abf3de8c46282b8d4da6d5da0/std/rangecheck/rangecheck_commit.go
type Type int

const (
	R1CS Type = iota
	SCS
)

type FrontendTyper interface {
	FrontendType() Type
}

type checkedVariable struct {
	v    frontend.Variable
	bits int
}

func getOptimalBasewidth(api frontend.API, collected []checkedVariable) int {
	if ft, ok := api.(FrontendTyper); ok {
		switch ft.FrontendType() {
		case R1CS:
			return optimalWidth(nbR1CSConstraints, collected)
		case SCS:
			return optimalWidth(nbPLONKConstraints, collected)
		}
	}
	return optimalWidth(nbR1CSConstraints, collected)
}

func optimalWidth(countFn func(baseLength int, collected []checkedVariable) int, collected []checkedVariable) int {
	min := math.MaxInt64
	minVal := 0
	for j := 2; j < 18; j++ {
		current := countFn(j, collected)
		if current < min {
			min = current
			minVal = j
		}
	}

	return minVal
}

func decompSize(varSize int, limbSize int) int {
	return (varSize + limbSize - 1) / limbSize
}

func nbR1CSConstraints(baseLength int, collected []checkedVariable) int {
	nbDecomposed := 0
	for i := range collected {
		nbDecomposed += int(decompSize(collected[i].bits, baseLength))
	}
	eqs := len(collected)       // correctness of decomposition
	nbRight := nbDecomposed     // inverse per decomposed
	nbleft := (1 << baseLength) // div per table
	return nbleft + nbRight + eqs + 1
}

func nbPLONKConstraints(baseLength int, collected []checkedVariable) int {
	nbDecomposed := 0
	for i := range collected {
		nbDecomposed += int(decompSize(collected[i].bits, baseLength))
	}
	eqs := nbDecomposed               // check correctness of every decomposition. this is nbDecomp adds + eq cost per collected
	nbRight := 3 * nbDecomposed       // denominator sub, inv and large sum per table entry
	nbleft := 3 * (1 << baseLength)   // denominator sub, div and large sum per table entry
	return nbleft + nbRight + eqs + 1 // and the final assert
}

func gnarkRangeCheckerSelector(api frontend.API) RangeCheckerType {
	// Emulate the logic within rangecheck.New
	// https://github.com/Consensys/gnark/blob/3421eaa7d544286abf3de8c46282b8d4da6d5da0/std/rangecheck/rangecheck.go#L24
	if _, ok := api.(frontend.Rangechecker); ok {
		return NATIVE_RANGE_CHECKER
	} else if _, ok := api.(frontend.Committer); ok {
		return COMMIT_RANGE_CHECKER
	} else {
		return BIT_DECOMP_RANGE_CHECKER
	}
}
