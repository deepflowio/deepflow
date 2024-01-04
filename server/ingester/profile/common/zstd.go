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

package common

import (
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("profile.common")

	decoder *zstd.Decoder
	encoder *zstd.Encoder

	encoderOnce, decoderOnce sync.Once
)

func ZstdDecompress(dst, src []byte) ([]byte, error) {
	decoderOnce.Do(func() {
		var err error
		decoder, err = zstd.NewReader(nil)
		if err != nil {
			log.Error(err)
		}
	})
	return decoder.DecodeAll(src, dst[:0])
}

func ZstdCompress(dst, src []byte, l zstd.EncoderLevel) ([]byte, error) {
	encoderOnce.Do(func() {
		var err error
		encoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(l))
		if err != nil {
			log.Error(err)
		}
	})
	return encoder.EncodeAll(src, dst[:0]), nil
}
