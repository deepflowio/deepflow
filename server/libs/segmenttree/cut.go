package segmenttree

const (
	POSITIVE_INFINITY = int64(^uint64(0) >> 1)
	NEGATIVE_INFINITY = -POSITIVE_INFINITY - 1
)

type Cut struct {
	endpoint int64
	closed   bool // bound等于正无穷或负无穷时，closed无效
}

func (c *Cut) compareTo(o Cut) int {
	if c.endpoint > o.endpoint {
		return 1
	} else if c.endpoint < o.endpoint {
		return -1
	} else if c.closed != o.closed {
		if c.closed {
			return 1
		} else {
			return -1
		}
	} else {
		return 0
	}
}

func (c *Cut) hasBound() bool {
	return c.endpoint != POSITIVE_INFINITY && c.endpoint != NEGATIVE_INFINITY
}
