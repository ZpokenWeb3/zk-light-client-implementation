package types

import (
	"encoding/json"
	"io"
	"os"
)

type ProofWithPublicInputsRaw struct {
	Proof struct {
		WiresCap                  []string `json:"wires_cap"`
		PlonkZsPartialProductsCap []string `json:"plonk_zs_partial_products_cap"`
		QuotientPolysCap          []string `json:"quotient_polys_cap"`
		Openings                  struct {
			Constants       [][]uint64 `json:"constants"`
			PlonkSigmas     [][]uint64 `json:"plonk_sigmas"`
			Wires           [][]uint64 `json:"wires"`
			PlonkZs         [][]uint64 `json:"plonk_zs"`
			PlonkZsNext     [][]uint64 `json:"plonk_zs_next"`
			PartialProducts [][]uint64 `json:"partial_products"`
			QuotientPolys   [][]uint64 `json:"quotient_polys"`
		} `json:"openings"`
		OpeningProof struct {
			CommitPhaseMerkleCaps [][]string `json:"commit_phase_merkle_caps"`
			QueryRoundProofs      []struct {
				InitialTreesProof struct {
					EvalsProofs []EvalProofRaw `json:"evals_proofs"`
				} `json:"initial_trees_proof"`
				Steps []struct {
					Evals       [][]uint64 `json:"evals"`
					MerkleProof struct {
						Siblings []string `json:"siblings"`
					} `json:"merkle_proof"`
				} `json:"steps"`
			} `json:"query_round_proofs"`
			FinalPoly struct {
				Coeffs [][]uint64 `json:"coeffs"`
			} `json:"final_poly"`
			PowWitness uint64 `json:"pow_witness"`
		} `json:"opening_proof"`
	} `json:"proof"`
	PublicInputs []uint64 `json:"public_inputs"`
}

type EvalProofRaw struct {
	LeafElements []uint64
	MerkleProof  MerkleProofRaw
}

func (e *EvalProofRaw) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &[]interface{}{&e.LeafElements, &e.MerkleProof})
}

type MerkleProofRaw struct {
	Hash []string
}

func (m *MerkleProofRaw) UnmarshalJSON(data []byte) error {
	type SiblingObject struct {
		Siblings []string // "siblings"
	}

	var siblings SiblingObject
	if err := json.Unmarshal(data, &siblings); err != nil {
		panic(err)
	}

	m.Hash = make([]string, len(siblings.Siblings))
	copy(m.Hash[:], siblings.Siblings)

	return nil
}

type ProofChallengesRaw struct {
	PlonkBetas    []uint64 `json:"plonk_betas"`
	PlonkGammas   []uint64 `json:"plonk_gammas"`
	PlonkAlphas   []uint64 `json:"plonk_alphas"`
	PlonkZeta     []uint64 `json:"plonk_zeta"`
	FriChallenges struct {
		FriAlpha        []uint64   `json:"fri_alpha"`
		FriBetas        [][]uint64 `json:"fri_betas"`
		FriPowResponse  uint64     `json:"fri_pow_response"`
		FriQueryIndices []uint64   `json:"fri_query_indices"`
	} `json:"fri_challenges"`
}

type VerifierOnlyCircuitDataRaw struct {
	ConstantsSigmasCap []string `json:"constants_sigmas_cap"`
	CircuitDigest      string   `json:"circuit_digest"`
}

func ReadProofWithPublicInputs(path string) ProofWithPublicInputsRaw {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw ProofWithPublicInputsRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return raw
}

func ReadProofWithPublicInputsFromRequest(data []byte) ProofWithPublicInputsRaw {
	var raw ProofWithPublicInputsRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		panic(err)
	}
	return raw
}

func ReadVerifierOnlyCircuitDataFromRequest(data []byte) VerifierOnlyCircuitDataRaw {
	var raw VerifierOnlyCircuitDataRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		panic(err)
	}
	return raw
}

func ReadVerifierOnlyCircuitData(path string) VerifierOnlyCircuitDataRaw {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw VerifierOnlyCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return raw
}
