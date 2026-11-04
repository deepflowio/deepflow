package datatype

import "testing"

func TestSplitPortRejectInvalidNumbers(t *testing.T) {
	for _, input := range []string{"65536", "70000", "1-65536", "100-80"} {
		if got := SplitPort2Int(input); len(got) != 0 {
			t.Fatalf("invalid port %q accepted as %v", input, got)
		}
	}
	for _, input := range []string{"0", "65535", "80-100"} {
		if got := SplitPort2Int(input); len(got) != 1 {
			t.Fatalf("valid port %q rejected", input)
		}
	}
}
