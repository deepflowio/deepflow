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

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"
)

func send(ip net.IP, interval float64, data []byte) {
	dst := &net.UDPAddr{IP: ip, Port: 20033}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(data) <= 0 {
		fmt.Println("data len is less then 0")
		return
	}

	seq := *seqn
	inport := 0x1
	tridentIndex := uint8(0)
	for {
		timestamp := time.Now().UnixNano() / 1000
		timestamp = int64(int(timestamp) + (*timeAdjust * 1000000))
		binary.BigEndian.PutUint32(data[2:], uint32(seq))
		binary.BigEndian.PutUint64(data[6:], uint64(timestamp)|uint64(tridentIndex)<<56)
		if *rand {
			binary.BigEndian.PutUint32(data[14:], uint32(inport))
			inport += 1
			tridentIndex += 1
		}
		conn.Write(data)
		if interval != 0 {
			time.Sleep(time.Duration(interval * float64(time.Second)))
		}
		//timestamp += 3000000
		seq += 1
	}
}

func getData(file string) []byte {
	var f *os.File
	f, _ = os.Open(file)
	r, _ := pcapgo.NewReader(f)
	defer f.Close()
	packet, _, err := r.ReadPacketData()
	if packet == nil || err != nil {
		return []byte{}
	}
	return packet[42:]
}

var ip = flag.String("d", "", "droplet node ip")
var interval = flag.Float64("i", 0, "packet send interval, second")
var file = flag.String("f", "", "send pcap")
var rand = flag.Bool("rand", false, "set inPort and dispatcher index increat")
var seqn = flag.Uint("seq", 1, "set seq")
var timeAdjust = flag.Int("t", 0, "time adjust")

func main() {
	flag.Parse()
	var data []byte
	if *file != "" {
		data = getData(*file)
	}
	send(net.ParseIP(*ip), *interval, data)
}
