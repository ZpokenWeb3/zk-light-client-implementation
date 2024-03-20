package gates

const UNUSED_SELECTOR = uint64(^uint32(0)) // max uint32

type Range struct {
	start uint64
	end   uint64
}

type SelectorsInfo struct {
	selectorIndices []uint64
	groups          []Range
}

func NewSelectorsInfo(selectorIndices []uint64, groupStarts []uint64, groupEnds []uint64) *SelectorsInfo {
	if len(groupStarts) != len(groupEnds) {
		panic("groupStarts and groupEnds must have the same length")
	}

	groups := []Range{}
	for i := range groupStarts {
		groups = append(groups, Range{
			start: groupStarts[i],
			end:   groupEnds[i],
		})
	}

	return &SelectorsInfo{
		selectorIndices: selectorIndices,
		groups:          groups,
	}
}

func (s *SelectorsInfo) NumSelectors() uint64 {
	return uint64(len(s.groups))
}
