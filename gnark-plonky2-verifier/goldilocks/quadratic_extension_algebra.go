package goldilocks

import "github.com/consensys/gnark-crypto/field/goldilocks"

const D = 2

type QuadraticExtensionAlgebraVariable = [D]QuadraticExtensionVariable

func NewQuadraticExtensionAlgebraVariable(
	a QuadraticExtensionVariable,
	b QuadraticExtensionVariable,
) QuadraticExtensionAlgebraVariable {
	return QuadraticExtensionAlgebraVariable{a, b}
}

func (p QuadraticExtensionVariable) ToQuadraticExtensionAlgebra() QuadraticExtensionAlgebraVariable {
	return [D]QuadraticExtensionVariable{p, ZeroExtension()}
}

func ZeroExtensionAlgebra() QuadraticExtensionAlgebraVariable {
	return ZeroExtension().ToQuadraticExtensionAlgebra()
}

func OneExtensionAlgebra() QuadraticExtensionAlgebraVariable {
	return OneExtension().ToQuadraticExtensionAlgebra()
}

func (p *Chip) AddExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var sum QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		sum[i] = p.AddExtension(a[i], b[i])
	}
	return sum
}

func (p *Chip) SubExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var diff QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		diff[i] = p.SubExtension(a[i], b[i])
	}
	return diff
}

func (p *Chip) MulExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var inner [D][]QuadraticExtensionAlgebraVariable
	var innerW [D][]QuadraticExtensionAlgebraVariable

	for i := 0; i < D; i++ {
		for j := 0; j < D-i; j++ {
			idx := (i + j) % D
			inner[idx] = append(inner[idx], QuadraticExtensionAlgebraVariable{a[i], b[j]})
		}
		for j := D - i; j < D; j++ {
			idx := (i + j) % D
			innerW[idx] = append(innerW[idx], QuadraticExtensionAlgebraVariable{a[i], b[j]})
		}
	}

	var product QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		acc := p.InnerProductExtension(NewVariable(W), ZeroExtension(), innerW[i])
		product[i] = p.InnerProductExtension(One(), acc, inner[i])
	}

	return product
}

func (p *Chip) ScalarMulExtensionAlgebra(
	a QuadraticExtensionVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var product QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		product[i] = p.MulExtension(a, b[i])
	}
	return product
}

func (p *Chip) PartialInterpolateExtAlgebra(
	domain []goldilocks.Element,
	values []QuadraticExtensionAlgebraVariable,
	barycentricWeights []goldilocks.Element,
	point QuadraticExtensionAlgebraVariable,
	initialEval QuadraticExtensionAlgebraVariable,
	initialPartialProd QuadraticExtensionAlgebraVariable,
) (QuadraticExtensionAlgebraVariable, QuadraticExtensionAlgebraVariable) {
	n := len(values)
	if n == 0 {
		panic("Cannot interpolate with no values")
	}
	if n != len(domain) {
		panic("Domain and values must have the same length")
	}
	if n != len(barycentricWeights) {
		panic("Domain and barycentric weights must have the same length")
	}

	newEval := initialEval
	newPartialProd := initialPartialProd
	for i := 0; i < n; i++ {
		val := values[i]
		x := domain[i]
		xField := NewVariable(x)
		xQE := xField.ToQuadraticExtension()
		xQEAlgebra := xQE.ToQuadraticExtensionAlgebra()
		weight := NewVariable(barycentricWeights[i].Uint64()).ToQuadraticExtension()
		term := p.SubExtensionAlgebra(point, xQEAlgebra)
		weightedVal := p.ScalarMulExtensionAlgebra(weight, val)
		newEval = p.MulExtensionAlgebra(newEval, term)
		tmp := p.MulExtensionAlgebra(weightedVal, newPartialProd)
		newEval = p.AddExtensionAlgebra(newEval, tmp)
		newPartialProd = p.MulExtensionAlgebra(newPartialProd, term)
	}

	return newEval, newPartialProd
}
