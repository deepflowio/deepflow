/*
 * Copyright (c) 2023 Yunshan Networks
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

package service

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	. "github.com/smartystreets/goconvey/convey"
)

func TestParseMatchersParam(t *testing.T) {
	Convey("TestCase_ParseMatchersParam_Failed", t, func() {
		matchers := []string{""}
		_, err := parseMatchersParam(matchers)
		So(err, ShouldNotBeNil)
	})

	// regular name parse
	Convey("TestCase_ParseMatchersParam_Success", t, func() {
		matchers := []string{
			// supported for query
			"demo_cpu_usage_seconds_total",
			"demo_memory_usage_bytes",
			// not supported for query, but support for parse
			`{__name__=".*"}`,
			`{job="prometheus-job"}`,
		}
		expected := [][]*labels.Matcher{
			{&labels.Matcher{Type: labels.MatchEqual, Name: "__name__", Value: "demo_cpu_usage_seconds_total"}},
			{&labels.Matcher{Type: labels.MatchEqual, Name: "__name__", Value: "demo_memory_usage_bytes"}},
			{&labels.Matcher{Type: labels.MatchEqual, Name: "__name__", Value: ".*"}},
			{&labels.Matcher{Type: labels.MatchEqual, Name: "job", Value: "prometheus-job"}},
		}
		labelMatcher, err := parseMatchersParam(matchers)
		So(err, ShouldBeNil)
		for i := 0; i < len(expected); i++ {
			So(labelMatcher[i][0].Type, ShouldEqual, expected[i][0].Type)
			So(labelMatcher[i][0].Name, ShouldEqual, expected[i][0].Name)
			So(labelMatcher[i][0].Value, ShouldEqual, expected[i][0].Value)
		}
	})

}
