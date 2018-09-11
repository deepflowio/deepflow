package flowgenerator

import (
	"testing"
)

func BenchmarkTaggedFlowAlloc(b *testing.B) {
	taggedFlowHandler := TaggedFlowHandler{}
	taggedFlowHandler.Init()
	for i := 0; i < b.N; i++ {
		taggedFlowHandler.alloc()
	}
}
