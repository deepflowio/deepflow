/*
 * Copyright (c) 2024 Yunshan Networks
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

package app

import (
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

func DecodePB(decoder *codec.SimpleDecoder, pbDoc *pb.Document) (*Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	err := decoder.ReadPB(pbDoc)
	if decoder.Failed() || err != nil {
		return nil, fmt.Errorf("Decode failed: %s", err)
	}

	doc := AcquireDocument()
	doc.Timestamp = pbDoc.Timestamp

	tag := flow_metrics.AcquireTag()
	tag.Field = flow_metrics.AcquireField()
	tag.ReadFromPB(pbDoc.Tag)
	doc.Tagger = tag

	meterID := uint8(pbDoc.Meter.MeterId)
	switch meterID {
	case flow_metrics.FLOW_ID:
		flowMeter := flow_metrics.AcquireFlowMeter()
		flowMeter.ReadFromPB(pbDoc.Meter.Flow)
		doc.Meter = flowMeter
	case flow_metrics.ACL_ID:
		usageMeter := flow_metrics.AcquireUsageMeter()
		usageMeter.ReadFromPB(pbDoc.Meter.Usage)
		doc.Meter = usageMeter
	case flow_metrics.APP_ID:
		appMeter := flow_metrics.AcquireAppMeter()
		appMeter.ReadFromPB(pbDoc.Meter.App)
		doc.Meter = appMeter
	default:
		return nil, fmt.Errorf("Unknow meter ID %d", meterID)

	}

	doc.Flags = DocumentFlag(pbDoc.Flags)
	return doc, nil
}

// queue monitor 打印时使用
func DecodeForQueueMonitor(decoder *codec.SimpleDecoder) (*Document, error) {
	pbDoc := &pb.Document{}
	decoder.ReadPB(pbDoc)
	if decoder.Failed() {
		return nil, errors.New("Decode failed")
	}

	doc := &Document{}
	doc.Timestamp = pbDoc.Timestamp

	tag := &flow_metrics.Tag{}
	tag.Field = &flow_metrics.Field{}
	tag.ReadFromPB(pbDoc.Tag)
	doc.Tagger = tag

	meterID := uint8(pbDoc.Meter.MeterId)
	switch meterID {
	case flow_metrics.FLOW_ID:
		flowMeter := flow_metrics.AcquireFlowMeter()
		flowMeter.ReadFromPB(pbDoc.Meter.Flow)
		doc.Meter = flowMeter
	case flow_metrics.ACL_ID:
		usageMeter := flow_metrics.AcquireUsageMeter()
		usageMeter.ReadFromPB(pbDoc.Meter.Usage)
		doc.Meter = usageMeter
	case flow_metrics.APP_ID:
		appMeter := flow_metrics.AcquireAppMeter()
		appMeter.ReadFromPB(pbDoc.Meter.App)
		doc.Meter = appMeter
	}

	doc.Flags = DocumentFlag(pbDoc.Flags)
	return doc, nil
}
