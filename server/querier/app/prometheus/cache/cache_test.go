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

package cache

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	cfg "github.com/deepflowio/deepflow/server/querier/app/prometheus/config"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/prometheus/prometheus/prompb"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	remoteReadCacheTestStorage      *RemoteReadQueryCache
	uniquePromReqs                  []*prompb.ReadRequest
	parsePrometheusRequestTestCases []TestCase[parseCacheItemOutput]

	prometheusCacheHitTestCases map[string][]TestCase[cacheHitResultOutput]
)

type cacheExternDirection int

const (
	externNone cacheExternDirection = iota
	externLeft
	externRight
	externBoth
)

type TestCase[T any] struct {
	input    *prompb.ReadRequest
	output   *T
	hasError bool
}

type parseCacheItemOutput struct {
	key    string
	metric string
	start  int64
	end    int64
}

type cacheHitResultOutput struct {
	hit    CacheHit
	extern cacheExternDirection
	starts int64
	ends   int64
}

func TestMain(m *testing.M) {
	config.Cfg = &config.QuerierConfig{Prometheus: cfg.Prometheus{Cache: cfg.PrometheusCache{
		Enabled:                true,
		CacheItemSize:          512,
		CacheMaxCount:          5,
		CacheMaxAllowDeviation: 60 * 60, // 60min
	}}}

	remoteReadCacheTestStorage = NewRemoteReadQueryCache()
	t := time.Now()

	parsePrometheusRequestTestCases = make([]TestCase[parseCacheItemOutput], 0, 3)
	parsePrometheusRequestTestCases = append(parsePrometheusRequestTestCases,
		// __name__
		TestCase[parseCacheItemOutput]{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"}},
						Hints: &prompb.ReadHints{
							StartMs: t.UnixMilli(),
							EndMs:   t.Add(30 * time.Minute).UnixMilli(),
							StepMs:  5000,
						},
					},
				},
			},
			output: &parseCacheItemOutput{
				key:    "__name__EQnode_cpu_seconds_total-",
				metric: "node_cpu_seconds_total",
				start:  t.Unix(),
				end:    t.Add(30 * time.Minute).Unix(),
			},
		},
		// __name__job
		TestCase[parseCacheItemOutput]{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_RE, Name: "job", Value: "prometheus.*"},
						},
						Hints: &prompb.ReadHints{
							StartMs: t.UnixMilli(),
							EndMs:   t.Add(30 * time.Minute).UnixMilli(),
							StepMs:  1000,
						},
					},
				},
			},
			output: &parseCacheItemOutput{
				key:    "__name__EQnode_cpu_seconds_total-jobREprometheus.*-",
				metric: "node_cpu_seconds_total",
				start:  t.Unix(),
				end:    t.Add(30 * time.Minute).Unix(),
			},
		},
		// __name__instance
		TestCase[parseCacheItemOutput]{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_NRE, Name: "instance", Value: "0.0.0.0"},
						},
						Hints: &prompb.ReadHints{
							StartMs: t.UnixMilli(),
							EndMs:   t.Add(30 * time.Minute).UnixMilli(),
							StepMs:  5000,
						},
					},
				},
			},
			output: &parseCacheItemOutput{
				key:    "__name__EQnode_cpu_seconds_total-instanceNRE0.0.0.0-",
				metric: "node_cpu_seconds_total",
				start:  t.Unix(),
				end:    t.Add(30 * time.Minute).Unix(),
			},
		})

	prometheusCacheHitTestCases = make(map[string][]TestCase[cacheHitResultOutput], 3)
	// __name__ case: left/right/both
	prometheusCacheHitTestCases["__name__EQnode_cpu_seconds_total-"] = []TestCase[cacheHitResultOutput]{
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
						},
						// last: [0, 30]
						//                merge
						// new:  [-10, 5] ====> [-10, 30]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.Add(-10 * time.Minute).UnixMilli()),
							EndMs:   t.Add(5 * time.Minute).UnixMilli(),
							StepMs:  3000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitPart, extern: externLeft, starts: leftAlignSeconds(t.Add(-10 * time.Minute).Unix()), ends: t.Add(5 * time.Minute).Unix()},
		},
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
						},
						// last: [0, 30]
						//               merge
						// new:  [0, 40] ====> [0, 40]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.UnixMilli()),
							EndMs:   t.Add(40 * time.Minute).UnixMilli(),
							StepMs:  5000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitPart, extern: externRight, starts: leftAlignSeconds(t.Unix()), ends: t.Add(40 * time.Minute).Unix()},
		},
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
						},
						// last: [0, 30]
						//                 merge
						// new:  [-40, 45] ====> [-40, 45]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.Add(-40 * time.Minute).UnixMilli()),
							EndMs:   t.Add(45 * time.Minute).UnixMilli(),
							StepMs:  5000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitPart, extern: externBoth, starts: leftAlignSeconds(t.Add(-40 * time.Minute).Unix()), ends: t.Add(45 * time.Minute).Unix()},
		},
	}

	// __name__job case: full / left miss / right miss
	prometheusCacheHitTestCases["__name__EQnode_cpu_seconds_total-jobREprometheus.*-"] = []TestCase[cacheHitResultOutput]{
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_RE, Name: "job", Value: "prometheus.*"},
						},
						// last: [0, 30]
						//                none
						// new:  [5, 15] ======> [0, 30]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.Add(5 * time.Minute).UnixMilli()),
							EndMs:   t.Add(15 * time.Minute).UnixMilli(),
							StepMs:  300,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitFull, extern: externNone, starts: leftAlignSeconds(t.Unix()), ends: t.Add(30 * time.Minute).Unix()},
		},
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_RE, Name: "job", Value: "prometheus.*"},
						},
						// last: [0, 30]
						//                 replace
						// new:  [-10, -5] =======> [-10, -5]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.Add(-10 * time.Minute).UnixMilli()),
							EndMs:   t.Add(-5 * time.Minute).UnixMilli(),
							StepMs:  1000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheMiss, extern: externNone, starts: leftAlignSeconds(t.Add(-10 * time.Minute).Unix()), ends: t.Add(-5 * time.Minute).Unix()},
		},
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_RE, Name: "job", Value: "prometheus.*"},
						},
						// last: [0, 30]
						//                replace
						// new:  [35, 40] =======> [35, 40]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.Add(35 * time.Minute).UnixMilli()),
							EndMs:   t.Add(40 * time.Minute).UnixMilli(),
							StepMs:  200,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheMiss, extern: externNone, starts: leftAlignSeconds(t.Add(35 * time.Minute).Unix()), ends: t.Add(40 * time.Minute).Unix()},
		},
	}

	// __name__instanc case: query / backoff
	prometheusCacheHitTestCases["__name__EQnode_cpu_seconds_total-instanceNRE0.0.0.0-"] = []TestCase[cacheHitResultOutput]{
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_NRE, Name: "instance", Value: "0.0.0.0"},
						},
						// last: [0, 30]
						//               merge
						// new:  [0, 45] =====> [0, 45]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.UnixMilli()),
							EndMs:   t.Add(45 * time.Minute).UnixMilli(),
							StepMs:  300,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitPart, extern: externRight, starts: leftAlignSeconds(t.Unix()), ends: t.Add(45 * time.Minute).Unix()},
		},
		// backoff
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_NRE, Name: "instance", Value: "0.0.0.0"},
						},
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.UnixMilli()),
							EndMs:   t.Add(30 * time.Minute).UnixMilli(),
							StepMs:  2000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitFull, extern: externNone, starts: leftAlignSeconds(t.Unix()), ends: t.Add(30 * time.Minute).Unix()},
		},

		// query backward
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_NRE, Name: "instance", Value: "0.0.0.0"},
						},
						// last: [0, 30]
						//                 merge
						// new:  [-15, 30] =====> [-15, 30]
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.Add(-15 * time.Minute).UnixMilli()),
							EndMs:   t.Add(30 * time.Minute).UnixMilli(),
							StepMs:  2000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitPart, extern: externLeft, starts: leftAlignSeconds(t.Add(-15 * time.Minute).Unix()), ends: t.Add(30 * time.Minute).Unix()},
		},
		// backoff
		{
			input: &prompb.ReadRequest{
				Queries: []*prompb.Query{
					{
						Matchers: []*prompb.LabelMatcher{
							{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "node_cpu_seconds_total"},
							{Type: prompb.LabelMatcher_NRE, Name: "instance", Value: "0.0.0.0"},
						},
						Hints: &prompb.ReadHints{
							StartMs: leftAlignMs(t.UnixMilli()),
							EndMs:   t.Add(30 * time.Minute).UnixMilli(),
							StepMs:  2000,
						},
					},
				},
			},
			output: &cacheHitResultOutput{hit: CacheHitFull, extern: externNone, starts: leftAlignSeconds(t.Unix()), ends: t.Add(30 * time.Minute).Unix()},
		},
	}

	// same key, different query range
	for i := 0; i < len(parsePrometheusRequestTestCases); i++ {
		uniquePromReqs = append(uniquePromReqs, parsePrometheusRequestTestCases[i].input)
	}

	m.Run()
}

func TestPromRequestToCacheKey(t *testing.T) {
	Convey("TestPromRequestToCacheKey", t, func() {
		for i := 0; i < len(parsePrometheusRequestTestCases); i++ {
			start, end := GetPromRequestQueryTime(parsePrometheusRequestTestCases[i].input.Queries[0])
			key, m := promRequestToCacheKey(parsePrometheusRequestTestCases[i].input.Queries[0])
			So(key, ShouldEqual, parsePrometheusRequestTestCases[i].output.key)
			So(start, ShouldEqual, parsePrometheusRequestTestCases[i].output.start)
			So(end, ShouldBeGreaterThanOrEqualTo, parsePrometheusRequestTestCases[i].output.end)
			So(m, ShouldEqual, parsePrometheusRequestTestCases[i].output.metric)

			for j := 0; j < len(parsePrometheusRequestTestCases); j++ {
				if i == j {
					continue
				}
				innerKey, _ := promRequestToCacheKey(parsePrometheusRequestTestCases[j].input.Queries[0])
				So(key, ShouldNotEqual, innerKey)
			}
		}
	})
}

func buildCacheItem(start, end int64, index int, m string) *common.Result {
	return &common.Result{
		Values: []interface{}{
			[]interface{}{start, end, index, m},
		},
	}
}

func asyncCacheGenerator() chan CacheHit {
	c := make(chan CacheHit)
	go func() {
		for k, v := range uniquePromReqs {
			item, hit, m, start, end := remoteReadCacheTestStorage.Get(v)
			var cache *common.Result
			if item != nil {
				cache = item.data
			}
			c <- hit
			data := buildCacheItem(start, end, k, m)
			remoteReadCacheTestStorage.AddOrMerge(v, item, cache, data)
		}

		close(c)
	}()
	return c
}

func leftAlignMs(t int64) int64 {
	return t - t%60000
}

func leftAlignSeconds(t int64) int64 {
	return t - t%60
}

func TestCacheHit(t *testing.T) {
	Convey("TestCacheHit", t, func() {
		// cache hit should happend after miss
		for i := range asyncCacheGenerator() {
			So(i, ShouldEqual, CacheMiss)
		}

		for _, v := range uniquePromReqs {
			item, hit, _, start, end := remoteReadCacheTestStorage.Get(v)
			start_align := timeAlign(v.Queries[0].Hints.StartMs / 1000)
			end_align := v.Queries[0].Hints.EndMs / 1000
			if v.Queries[0].Hints.EndMs%1000 != 0 {
				end_align += 1
			}

			So(hit, ShouldEqual, CacheHitFull)
			So(item, ShouldNotBeNil)
			So(len(item.data.Values), ShouldBeGreaterThan, 0)
			So(start, ShouldEqual, start_align)
			So(end, ShouldEqual, end_align)
		}
	})
}

func TestCacheMiss(t *testing.T) {
	Convey("TestCacheMiss", t, func() {
		for i := range asyncCacheGenerator() {
			So(i, ShouldEqual, CacheMiss)
		}
	})
}

var lock *sync.Mutex = &sync.Mutex{}

func resetCacheItem(key string, ori *CacheItem, s1, e1 int64) {
	lock.Lock()
	defer lock.Unlock()

	ori.startTime = s1
	ori.endTime = e1
}

func TestCacheIntegration(t *testing.T) {
	Convey("TestCacheIntegration", t, func() {
		// first time, should miss
		for i := range asyncCacheGenerator() {
			So(i, ShouldEqual, CacheMiss)
		}

		// second time, should hit
		for _, v := range uniquePromReqs {
			item, hit, _, start, end := remoteReadCacheTestStorage.Get(v)

			start_align := timeAlign(v.Queries[0].Hints.StartMs / 1000)
			end_align := v.Queries[0].Hints.EndMs / 1000
			if v.Queries[0].Hints.EndMs%1000 != 0 {
				end_align += 1
			}

			So(hit, ShouldEqual, CacheHitFull)
			So(item, ShouldNotBeNil)
			So(len(item.data.Values), ShouldBeGreaterThan, 0)
			So(start, ShouldEqual, start_align)
			So(end, ShouldEqual, end_align)
		}
	})
	Convey("TestCacheIntegration_goroutine_10", t, func() {
		// for repeated reqs
		for i := 0; i < 10; i++ {
			tn := t
			go func(ti *testing.T) {
				iterateTestCases(ti)
			}(tn)
		}
	})
}

func iterateTestCases(t *testing.T) {
	for k, v := range prometheusCacheHitTestCases {
		for i := 0; i < len(v); i++ {
			t.Logf("TestCase: %s, index: %d", k, i)
			if strings.Contains(k, "instance") {
				fmt.Println(k)
			}
			item, hit, m, start, end := remoteReadCacheTestStorage.Get(v[i].input)
			var cache *common.Result
			if item != nil {
				cache = item.data
			}
			// cache hit judgement
			So(hit, ShouldEqual, v[i].output.hit)
			_ = remoteReadCacheTestStorage.AddOrMerge(v[i].input, item, cache, buildCacheItem(start, end, i, m))
			//So(len(result.Values), ShouldBeGreaterThan, 0)
			_, _, newM, newStart, newEnd := remoteReadCacheTestStorage.Get(v[i].input)
			So(m, ShouldEqual, newM)
			if item != nil {
				resetCacheItem(k, item, start, end)
			}
			output_start_align := timeAlign(v[i].output.starts)
			switch v[i].output.extern {
			case externNone:
				if hit == CacheHitFull {
					So(newStart, ShouldBeGreaterThanOrEqualTo, output_start_align)
					So(newEnd, ShouldBeLessThanOrEqualTo, v[i].output.ends)
				} else if hit == CacheMiss {
					So(newStart, ShouldEqual, output_start_align)
					So(newEnd, ShouldEqual, v[i].output.ends)
				}
			case externLeft:
				So(newStart, ShouldEqual, output_start_align)
			case externRight:
				So(newEnd, ShouldEqual, v[i].output.ends)
			case externBoth:
				So(newStart, ShouldEqual, output_start_align)
				So(newEnd, ShouldEqual, v[i].output.ends)
			}
		}
	}
}

func TestConcurrencyCacheGet(t *testing.T) {
	Convey("TestConcurrency_Prepare", t, func() {
		for i := range asyncCacheGenerator() {
			So(i, ShouldEqual, CacheMiss)
		}
	})

	wg := &sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(w *sync.WaitGroup) {
			r, e := rand.Int(rand.Reader, big.NewInt(300))
			if e != nil {
				t.Error(e)
			}
			iterateCacheReplaseTestCases("__name__EQnode_cpu_seconds_total-", time.Duration(r.Int64()*int64(time.Millisecond)))
			w.Done()
		}(wg)
	}
	wg.Wait()
}

func iterateCacheReplaseTestCases(key string, randomWait time.Duration) {
	for i := 0; i < len(prometheusCacheHitTestCases[key]); i++ {
		v := prometheusCacheHitTestCases[key][i]
		item, _, m, _, _ := remoteReadCacheTestStorage.Get(v.input)
		var cache *common.Result
		if item != nil {
			cache = item.Data()
		}
		time.Sleep(randomWait)
		_ = remoteReadCacheTestStorage.AddOrMerge(v.input, item, cache, buildCacheItem(v.output.starts, v.output.ends, i, m))
		hit := item.Hit(v.output.starts, v.output.ends)
		if hit != CacheHitFull {
			panic("cache result is modify by another goroutine")
		}
	}
}
