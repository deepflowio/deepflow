package prometheus

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
