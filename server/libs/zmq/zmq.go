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

package zmq

import "io"

type ClientOrServer int

const (
	CLIENT ClientOrServer = iota
	SERVER
)

type Sender interface {
	Send(b []byte) (n int, err error)
	SendNoBlock(b []byte) (n int, err error)
	io.Closer
}

type Receiver interface {
	Recv() ([]byte, error)
	RecvNoBlock() ([]byte, error)
	io.Closer
}
