package datatype

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
)

type Tag struct {
	PolicyData [2]PolicyData
}

func (t *Tag) Encode(encoder *codec.SimpleEncoder) {
	t.PolicyData[0].Encode(encoder)
	t.PolicyData[1].Encode(encoder)
}

func (t *Tag) Decode(decoder *codec.SimpleDecoder) {
	t.PolicyData[0].Decode(decoder)
	t.PolicyData[1].Decode(decoder)
}

func (t *Tag) Reverse() {
	t.PolicyData[0], t.PolicyData[1] = t.PolicyData[1], t.PolicyData[0]
}
