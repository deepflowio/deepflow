package timemap

import "fmt"

type Entry interface {
	Timestamp() uint32
	SetTimestamp(timestamp uint32)
	// Hash和Eq与timestamp没关系
	// 换句话说，调用了SetTimestamp或Merge之后，Hash不应该改变
	Hash() uint64
	Eq(other Entry) bool
	Merge(other Entry)
	Clone() Entry
	Release()
	fmt.Stringer
}
