package idmap

type Counter struct {
	Max  int `statsd:"max-bucket"`
	Size int `statsd:"size"`
}
