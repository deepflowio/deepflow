package datatype

import "testing"

func TestSplitPortMaxRangeMerge(t *testing.T) {
	for _, input := range []string{"0-65535,80", "80-65535,90-100", "65535,65535"} {
		ranges := SplitPort2Int(input)
		if len(ranges) != 1 {
			t.Fatalf("%q produced %d ranges: %v", input, len(ranges), ranges)
		}
		if ranges[0].Max() != 65535 {
			t.Fatalf("%q lost upper endpoint", input)
		}
	}
}
