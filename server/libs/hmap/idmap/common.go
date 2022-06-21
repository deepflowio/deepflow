package idmap

type Counter struct {
	Max     int `statsd:"max-bucket"`
	Size    int `statsd:"size"`
	AvgScan int `statsd:"avg-scan"` // 平均扫描次数

	totalScan, scanTimes int
}
