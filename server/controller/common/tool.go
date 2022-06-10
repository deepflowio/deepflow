package common

type Comparable interface {
	~int | ~string
}

func Contains[T Comparable](slice []T, val T) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
