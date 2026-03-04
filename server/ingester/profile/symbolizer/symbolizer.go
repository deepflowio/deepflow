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

package symbolizer

// InterpreterFrame is the server-side representation of an interpreter stack frame.
// It mirrors the protobuf InterpreterFrameSymbol message.
type InterpreterFrame struct {
	FrameType     int32
	FunctionName  string
	ClassName     string
	Lineno        uint32
	FileName      string
	SubType       uint32
	IsJIT         bool
	RawAddr       uint64
	ResolveFailed bool
}

// InterpreterType constants matching protobuf InterpreterFrameType enum values.
const (
	FrameTypeUnknown = 0
	FrameTypePython  = 1
	FrameTypePHP     = 2
	FrameTypeV8      = 3
	FrameTypeLua     = 4
)

// Symbolize is a stub for the open-source edition.
// The enterprise edition provides the full implementation that formats interpreter
// frames and merges them with the native stack trace.
// In the open-source edition, interpreter frames are ignored and the native stack
// trace is returned as-is.
func Symbolize(frames []*InterpreterFrame, nativeStackTrace string) string {
	return nativeStackTrace
}
