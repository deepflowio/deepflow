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

package utils

import (
	"github.com/deepflowio/deepflow/server/libs/pool"
)

type ByteBuffer struct {
	buf    []byte
	offset int
	quota  int

	pool.ReferenceCount // for PseudoClone
}

// 返回下一个可用的[]byte，自动增长空间
func (b *ByteBuffer) Use(n int) []byte {
	b.offset += n
	if b.offset > b.quota {
		panic("Quota limit exceeded!") // 对忘记调用Reset的保护
	}
	if b.offset > len(b.buf) {
		b.buf = append(b.buf, make([]byte, (b.offset-len(b.buf))*2)...)
	}
	return b.buf[b.offset-n : b.offset]
}

// 返回所有Use调用过的[]byte
func (b *ByteBuffer) Bytes() []byte {
	return b.buf[:b.offset]
}

func (b *ByteBuffer) Reset() {
	b.offset = 0
}

func (b *ByteBuffer) SetQuota(n int) {
	b.quota = n
}

var byteBufferPool = pool.NewLockFreePool(func() interface{} {
	return &ByteBuffer{quota: 1 << 16}
})

func AcquireByteBuffer() *ByteBuffer {
	b := byteBufferPool.Get().(*ByteBuffer)
	b.ReferenceCount.Reset()
	return b
}

func CloneByteBuffer(bytes *ByteBuffer) *ByteBuffer {
	clone := AcquireByteBuffer()
	clone.Use(len(bytes.Bytes()))
	copy(clone.Bytes(), bytes.Bytes())
	return clone
}

func PseudoCloneByteBuffer(bytes *ByteBuffer) {
	bytes.AddReferenceCount()
}

func ReleaseByteBuffer(bytes *ByteBuffer) {
	if bytes.SubReferenceCount() {
		return
	}
	bytes.Reset()
	byteBufferPool.Put(bytes)
}
