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

package datatype

import (
	"testing"

	"github.com/deepflowio/deepflow/server/libs/datatype"
)

type TestCase struct {
	in      string
	out     string
	max_len int
}

func TestTrimCommand(t *testing.T) {
	cases := []TestCase{
		TestCase{in: "sEleCt 1", out: "SELECT", max_len: 6},
		TestCase{in: "sEleCt 1", out: "SELECT", max_len: 7},
		TestCase{in: "sEleCt 1", out: "SELEC", max_len: 5},
		TestCase{in: "/* i am comment */SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* i am comment */ SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* i am comment */ /*i am comment*/ SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* i am comment */ /*i am comment*/SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* i am comment * /*/ SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* i am comment *  /**/  /**  */ SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* unable to parse */SelecT", out: "SELECT", max_len: 6},
		TestCase{in: "/* able to parse */SelecT ", out: "SELECT", max_len: 6},
		TestCase{in: "/* not a comment * / SelecT 1", out: "", max_len: 6},
		TestCase{in: "/ * not a comment */ SelecT 1", out: "", max_len: 6},
		TestCase{in: "/* i am comment /* */ syntax error /* i am comment */ SelecT 1", out: "SELECT", max_len: 6},
		TestCase{in: "/* i am comment /* */ -- syntax error /* i am comment */ SelecT 1", out: "SELECT", max_len: 6},
		//TestCase{in: "/ * not a comment *\/ SelecT 1", out: "", max_len: 6},
		TestCase{in: "/ * not a comment  /*/*  */ SelecT 1", out: "", max_len: 6},
	}
	for i, c := range cases {
		r := datatype.TrimCommand(c.in, c.max_len)
		if r != c.out {
			t.Errorf("Case: Id %d %v faild, return %v", i, c, r)
		}
	}
}
