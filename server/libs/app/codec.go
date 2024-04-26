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
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

func DecodePB(decoder *codec.SimpleDecoder, pbDoc *pb.Document) (Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	err := decoder.ReadPB(pbDoc)
	if decoder.Failed() || err != nil {
		return nil, fmt.Errorf("Decode failed: %s", err)
	}

	meterID := uint8(pbDoc.Meter.MeterId)
	switch meterID {
	case flow_metrics.FLOW_ID:
		doc := AcquireDocumentFlow()
		doc.Timestamp = pbDoc.Timestamp
		doc.Flags = DocumentFlag(pbDoc.Flags)
		doc.Tag.ReadFromPB(pbDoc.Tag)
		doc.FlowMeter.ReadFromPB(pbDoc.Meter.Flow)
		return doc, nil
	case flow_metrics.ACL_ID:
		doc := AcquireDocumentUsage()
		doc.Timestamp = pbDoc.Timestamp
		doc.Flags = DocumentFlag(pbDoc.Flags)
		doc.Tag.ReadFromPB(pbDoc.Tag)
		doc.UsageMeter.ReadFromPB(pbDoc.Meter.Usage)
		return doc, nil
	case flow_metrics.APP_ID:
		doc := AcquireDocumentApp()
		doc.Timestamp = pbDoc.Timestamp
		doc.Flags = DocumentFlag(pbDoc.Flags)
		doc.Tag.ReadFromPB(pbDoc.Tag)
		doc.AppMeter.ReadFromPB(pbDoc.Meter.App)
		return doc, nil
	default:
		return nil, fmt.Errorf("Unknow meter ID %d", meterID)

	}
}

// queue monitor 打印时使用
func DecodeForQueueMonitor(decoder *codec.SimpleDecoder) (Document, error) {
	pbDoc := &pb.Document{}
	decoder.ReadPB(pbDoc)
	if decoder.Failed() {
		return nil, errors.New("Decode failed")
	}

	meterID := uint8(pbDoc.Meter.MeterId)
	switch meterID {
	case flow_metrics.FLOW_ID:
		doc := &DocumentFlow{}
		doc.Timestamp = pbDoc.Timestamp
		doc.Flags = DocumentFlag(pbDoc.Flags)
		doc.Tag.ReadFromPB(pbDoc.Tag)
		doc.FlowMeter.ReadFromPB(pbDoc.Meter.Flow)
		return doc, nil
	case flow_metrics.ACL_ID:
		doc := &DocumentUsage{}
		doc.Timestamp = pbDoc.Timestamp
		doc.Flags = DocumentFlag(pbDoc.Flags)
		doc.Tag.ReadFromPB(pbDoc.Tag)
		doc.UsageMeter.ReadFromPB(pbDoc.Meter.Usage)
		return doc, nil
	case flow_metrics.APP_ID:
		doc := &DocumentApp{}
		doc.Timestamp = pbDoc.Timestamp
		doc.Flags = DocumentFlag(pbDoc.Flags)
		doc.Tag.ReadFromPB(pbDoc.Tag)
		doc.AppMeter.ReadFromPB(pbDoc.Meter.App)
		return doc, nil
	default:
		return nil, fmt.Errorf("Unknow meter ID %d", meterID)
	}
}
