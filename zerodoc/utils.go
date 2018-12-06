package zerodoc

import "time"

func maxU64(vs ...uint64) uint64 {
	if len(vs) == 0 {
		panic("no number provided")
	}
	max := vs[0]
	for _, v := range vs {
		if v > max {
			max = v
		}
	}
	return max
}

func minU64(vs ...uint64) uint64 {
	if len(vs) == 0 {
		panic("no number provided")
	}
	min := vs[0]
	for _, v := range vs {
		if v < min {
			min = v
		}
	}
	return min
}

func maxDuration(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

func minDuration(x, y time.Duration) time.Duration {
	if x == 0 || y == 0 {
		return x + y
	}
	if x < y {
		return x
	}
	return y
}
