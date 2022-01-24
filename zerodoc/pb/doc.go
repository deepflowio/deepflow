package pb

func NewDocument() *Document {
	return &Document{
		Minitag: &MiniTag{
			Field: &MiniField{},
		},
		Meter: &Meter{
			Flow: &FlowMeter{
				Traffic:     &Traffic{},
				Latency:     &Latency{},
				Performance: &Performance{},
				Anomaly:     &Anomaly{},
				Flowload:    &FlowLoad{},
			},
			Usage: &UsageMeter{},
			App: &AppMeter{
				AppTriffic: &AppTriffic{},
				AppLatency: &AppLatency{},
				AppAnomaly: &AppAnomaly{},
			},
		},
	}
}

// 清空pb的Document使解码时可以反复使用
func (d *Document) ResetAll() {
	miniTag := d.Minitag
	field := miniTag.Field
	ip0 := field.RawIP
	if ip0 != nil {
		ip0 = ip0[:0]
	}
	ip1 := field.RawIP1
	if ip1 != nil {
		ip1 = ip1[:0]
	}
	field.Reset()
	field.RawIP = ip0
	field.RawIP1 = ip1

	miniTag.Reset()
	miniTag.Field = field

	meter := d.Meter

	flow := meter.Flow
	traffic := flow.Traffic
	traffic.Reset()
	latency := flow.Latency
	latency.Reset()
	performance := flow.Performance
	performance.Reset()
	anomaly := flow.Anomaly
	anomaly.Reset()
	flowload := flow.Flowload
	flowload.Reset()

	flow.Reset()
	flow.Traffic = traffic
	flow.Latency = latency
	flow.Performance = performance
	flow.Anomaly = anomaly
	flow.Flowload = flowload

	usage := meter.Usage
	usage.Reset()

	app := meter.App
	appTriffic := app.AppTriffic
	appTriffic.Reset()
	appLatency := app.AppLatency
	appLatency.Reset()
	appAnomaly := app.AppAnomaly
	appAnomaly.Reset()

	app.Reset()
	app.AppTriffic = appTriffic
	app.AppLatency = appLatency
	app.AppAnomaly = appAnomaly

	meter.Reset()
	meter.Flow = flow
	meter.Usage = usage
	meter.App = app

	d.Reset()
	d.Minitag = miniTag
	d.Meter = meter
}
