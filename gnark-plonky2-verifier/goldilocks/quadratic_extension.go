package goldilocks

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

const W uint64 = 7
const DTH_ROOT uint64 = 18446744069414584320

type QuadraticExtensionVariable [2]Variable

func NewQuadraticExtensionVariable(x Variable, y Variable) QuadraticExtensionVariable {
	return QuadraticExtensionVariable{x, y}
}

func (p Variable) ToQuadraticExtension() QuadraticExtensionVariable {
	return NewQuadraticExtensionVariable(p, Zero())
}

func ZeroExtension() QuadraticExtensionVariable {
	return Zero().ToQuadraticExtension()
}

func OneExtension() QuadraticExtensionVariable {
	return One().ToQuadraticExtension()
}

// Adds two quadratic extension variables in the Goldilocks field.
func (p *Chip) AddExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.Add(a[0], b[0])
	c1 := p.Add(a[1], b[1])
	return NewQuadraticExtensionVariable(c0, c1)
}

// Adds two quadratic extension variables in the Goldilocks field without reducing.
func (p *Chip) AddExtensionNoReduce(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.AddNoReduce(a[0], b[0])
	c1 := p.AddNoReduce(a[1], b[1])
	return NewQuadraticExtensionVariable(c0, c1)
}

// Subtracts two quadratic extension variables in the Goldilocks field.
func (p *Chip) SubExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.Sub(a[0], b[0])
	c1 := p.Sub(a[1], b[1])
	return NewQuadraticExtensionVariable(c0, c1)
}

// Subtracts two quadratic extension variables in the Goldilocks field without reducing.
func (p *Chip) SubExtensionNoReduce(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.SubNoReduce(a[0], b[0])
	c1 := p.SubNoReduce(a[1], b[1])
	return NewQuadraticExtensionVariable(c0, c1)
}

// Multiplies quadratic extension variable in the Goldilocks field.
func (p *Chip) MulExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	product := p.MulExtensionNoReduce(a, b)
	return p.ReduceExtension(product)
}

// Multiplies quadratic extension variable in the Goldilocks field without reducing.
func (p *Chip) MulExtensionNoReduce(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0o0 := p.MulNoReduce(a[0], b[0])
	c0o1 := p.MulNoReduce(p.MulNoReduce(NewVariable(W), a[1]), b[1])
	c0 := p.AddNoReduce(c0o0, c0o1)
	c1 := p.AddNoReduce(p.MulNoReduce(a[0], b[1]), p.MulNoReduce(a[1], b[0]))
	return NewQuadraticExtensionVariable(c0, c1)
}

// Multiplies two operands a and b and adds to c in the Goldilocks extension field. a * b + c must
// be less than RANGE_CHECK_NB_BITS bits.
func (p *Chip) MulAddExtension(a, b, c QuadraticExtensionVariable) QuadraticExtensionVariable {
	product := p.MulExtensionNoReduce(a, b)
	sum := p.AddExtensionNoReduce(product, c)
	return p.ReduceExtension(sum)
}

func (p *Chip) MulAddExtensionNoReduce(a, b, c QuadraticExtensionVariable) QuadraticExtensionVariable {
	product := p.MulExtensionNoReduce(a, b)
	sum := p.AddExtensionNoReduce(product, c)
	return sum
}

// Subtracts two operands a and b and multiplies the diff by c in the Goldilocks extension field. (a - b) * c must
// be less than RANGE_CHECK_NB_BITS bits.
func (p *Chip) SubMulExtension(a, b, c QuadraticExtensionVariable) QuadraticExtensionVariable {
	difference := p.SubExtensionNoReduce(a, b)
	product := p.MulExtensionNoReduce(difference, c)
	return p.ReduceExtension(product)
}

// Multiplies quadratic extension variable in the Goldilocks field by a scalar.
func (p *Chip) ScalarMulExtension(
	a QuadraticExtensionVariable,
	b Variable,
) QuadraticExtensionVariable {
	return NewQuadraticExtensionVariable(
		p.Mul(a[0], b),
		p.Mul(a[1], b),
	)
}

// Computes an inner product over quadratic extension variable vectors in the Goldilocks field.
func (p *Chip) InnerProductExtension(
	constant Variable,
	startingAcc QuadraticExtensionVariable,
	pairs [][2]QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	acc := startingAcc
	for i := 0; i < len(pairs); i++ {
		a := pairs[i][0]
		b := pairs[i][1]
		mul := p.ScalarMulExtension(a, constant)
		acc = p.MulAddExtensionNoReduce(mul, b, acc)
	}
	return p.ReduceExtension(acc)
}

// Computes the inverse of a quadratic extension variable in the Goldilocks field.
func (p *Chip) InverseExtension(a QuadraticExtensionVariable) (QuadraticExtensionVariable, frontend.Variable) {
	aIsZero := p.IsZero(a)
	p.api.AssertIsEqual(aIsZero, frontend.Variable(0))
	aPowRMinus1 := QuadraticExtensionVariable{
		a[0],
		p.Mul(a[1], NewVariable(DTH_ROOT)),
	}
	aPowR := p.MulExtension(aPowRMinus1, a)

	aPowRInv, hasInv := p.Inverse(aPowR[0])
	return p.ScalarMulExtension(aPowRMinus1, aPowRInv), hasInv
}

// Divides two quadratic extension variables in the Goldilocks field.
func (p *Chip) DivExtension(a, b QuadraticExtensionVariable) (QuadraticExtensionVariable, frontend.Variable) {
	bInv, hasInv := p.InverseExtension(b)
	return p.MulExtension(a, bInv), hasInv
}

// Exponentiates a quadratic extension variable to some exponent in the Golidlocks field.
func (p *Chip) ExpExtension(
	a QuadraticExtensionVariable,
	exponent uint64,
) QuadraticExtensionVariable {
	switch exponent {
	case 0:
		return OneExtension()
	case 1:
		return a
	case 2:
		return p.MulExtension(a, a)
	default:
	}

	current := a
	product := OneExtension()

	for i := 0; i < bits.Len64(exponent); i++ {
		if i != 0 {
			current = p.MulExtension(current, current)
		}
		if (exponent >> i & 1) != 0 {
			product = p.MulExtension(product, current)
		}
	}

	return product
}

func (p *Chip) ReduceExtension(x QuadraticExtensionVariable) QuadraticExtensionVariable {
	return NewQuadraticExtensionVariable(p.Reduce(x[0]), p.Reduce(x[1]))
}

// Reduces a list of extension field terms with a scalar power in the Goldilocks field.
func (p *Chip) ReduceWithPowers(
	terms []QuadraticExtensionVariable,
	scalar QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	sum := ZeroExtension()
	for i := len(terms) - 1; i >= 0; i-- {
		sum = p.AddExtensionNoReduce(
			p.MulExtensionNoReduce(
				sum,
				scalar,
			),
			terms[i],
		)
		sum = p.ReduceExtension(sum)
	}
	return sum
}

// Outputs whether the quadratic extension variable is zero.
func (p *Chip) IsZero(x QuadraticExtensionVariable) frontend.Variable {
	x0IsZero := p.api.IsZero(x[0].Limb)
	x1IsZero := p.api.IsZero(x[1].Limb)
	return p.api.Mul(x0IsZero, x1IsZero)
}

// Lookup is similar to select, but returns the first variable if the bit is zero and vice-versa.
func (p *Chip) Lookup(
	b frontend.Variable,
	x, y QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	c0 := p.api.Select(b, y[0].Limb, x[0].Limb)
	c1 := p.api.Select(b, y[1].Limb, x[1].Limb)
	return NewQuadraticExtensionVariable(NewVariable(c0), NewVariable(c1))
}

// Lookup2 is similar to Lookup2.  It returns the ith qe value (0 indexed) where i is bit decomposed to b0,b1 (little endian).
func (p *Chip) Lookup2(
	b0 frontend.Variable,
	b1 frontend.Variable,
	qe0, qe1, qe2, qe3 QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	c0 := p.Lookup(b0, qe0, qe1)
	c1 := p.Lookup(b0, qe2, qe3)
	return p.Lookup(b1, c0, c1)
}

// Asserts that two quadratic extension variables are equal.
func (p *Chip) AssertIsEqualExtension(
	a QuadraticExtensionVariable,
	b QuadraticExtensionVariable,
) {
	p.AssertIsEqual(a[0], b[0])
	p.AssertIsEqual(a[1], b[1])
}

func (p *Chip) RangeCheckQE(a QuadraticExtensionVariable) {
	p.RangeCheck(a[0])
	p.RangeCheck(a[1])
}
