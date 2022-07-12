/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pb

func NewDocument() *Document {
	return &Document{
		Tag: &MiniTag{
			Field: &MiniField{},
		},
		Meter: &Meter{
			Flow: &FlowMeter{
				Traffic:     &Traffic{},
				Latency:     &Latency{},
				Performance: &Performance{},
				Anomaly:     &Anomaly{},
				FlowLoad:    &FlowLoad{},
			},
			Usage: &UsageMeter{},
			App: &AppMeter{
				Traffic: &AppTraffic{},
				Latency: &AppLatency{},
				Anomaly: &AppAnomaly{},
			},
		},
	}
}

// 清空pb的Document使解码时可以反复使用
func (d *Document) ResetAll() {
	miniTag := d.Tag
	field := miniTag.Field
	ip0 := field.Ip
	if ip0 != nil {
		ip0 = ip0[:0]
	}
	ip1 := field.Ip1
	if ip1 != nil {
		ip1 = ip1[:0]
	}
	field.Reset()
	field.Ip = ip0
	field.Ip1 = ip1

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
	flowload := flow.FlowLoad
	flowload.Reset()

	flow.Reset()
	flow.Traffic = traffic
	flow.Latency = latency
	flow.Performance = performance
	flow.Anomaly = anomaly
	flow.FlowLoad = flowload

	usage := meter.Usage
	usage.Reset()

	app := meter.App
	appTraffic := app.Traffic
	appTraffic.Reset()
	appLatency := app.Latency
	appLatency.Reset()
	appAnomaly := app.Anomaly
	appAnomaly.Reset()

	app.Reset()
	app.Traffic = appTraffic
	app.Latency = appLatency
	app.Anomaly = appAnomaly

	meter.Reset()
	meter.Flow = flow
	meter.Usage = usage
	meter.App = app

	d.Reset()
	d.Tag = miniTag
	d.Meter = meter
}
