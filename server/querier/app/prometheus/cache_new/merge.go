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

package cachenew

import (
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/prompb"
)

// ---------------------------------------------------------------------------
// Generic sorted-slice merge
// ---------------------------------------------------------------------------

// mergeOrdered merges two time-ordered slices into a single ordered slice.
// The timestamp accessor ts must return a strictly monotone key for each element.
// Returns a fresh allocation; never aliases either input.
//
// This eliminates the duplicated 50-line implementations of mergeSamples and
// mergePoints, which differed only in type (prompb.Sample.Timestamp vs promql.Point.T).
func mergeOrdered[E any](existing, incoming []E, ts func(E) int64) []E {
	if len(existing) == 0 {
		out := make([]E, len(incoming))
		copy(out, incoming)
		return out
	}
	if len(incoming) == 0 {
		out := make([]E, len(existing))
		copy(out, existing)
		return out
	}

	existEnd := ts(existing[len(existing)-1])
	existStart := ts(existing[0])
	incomingStart := ts(incoming[0])
	incomingEnd := ts(incoming[len(incoming)-1])

	switch {
	case existEnd < incomingStart:
		// existing: [   ]  incoming:       [   ]  — pure append
		out := make([]E, len(existing)+len(incoming))
		copy(out, existing)
		copy(out[len(existing):], incoming)
		return out

	case existStart > incomingEnd:
		// existing:       [   ]  incoming: [   ]  — incoming prepends
		out := make([]E, len(incoming)+len(existing))
		copy(out, incoming)
		copy(out[len(incoming):], existing)
		return out

	case existEnd >= incomingStart && existEnd < incomingEnd:
		// existing: [   ]  incoming:   [   ]  — right-extend
		at := sort.Search(len(incoming), func(i int) bool { return ts(incoming[i]) > existEnd })
		out := make([]E, len(existing)+(len(incoming)-at))
		copy(out, existing)
		copy(out[len(existing):], incoming[at:])
		return out

	case existStart <= incomingEnd && existStart > incomingStart:
		// existing:   [   ]  incoming: [   ]  — left-extend
		at := sort.Search(len(incoming), func(i int) bool { return ts(incoming[i]) >= existStart })
		out := make([]E, at+len(existing))
		copy(out, incoming[:at])
		copy(out[at:], existing)
		return out

	default:
		// existing completely contains incoming (or identical); keep existing
		out := make([]E, len(existing))
		copy(out, existing)
		return out
	}
}

// mergeSamples merges two ordered []prompb.Sample slices.
func mergeSamples(existing, incoming []prompb.Sample) []prompb.Sample {
	return mergeOrdered(existing, incoming, func(s prompb.Sample) int64 { return s.Timestamp })
}

// mergePoints merges two ordered []promql.Point slices.
func mergePoints(existing, incoming []promql.Point) []promql.Point {
	return mergeOrdered(existing, incoming, func(p promql.Point) int64 { return p.T })
}

// ---------------------------------------------------------------------------
// prompb.ReadResponse merge
// ---------------------------------------------------------------------------

// mergePrompbResponse merges newData (covering [ns,ne]) into cached (covering [cs,ce]).
// Returns a completely fresh *prompb.ReadResponse; never mutates or aliases either input.
func mergePrompbResponse(cached *prompb.ReadResponse, cs, ce int64, newData *prompb.ReadResponse, ns, ne int64) *prompb.ReadResponse {
	log.Debugf("cache merge: new=[%d,%d] cached=[%d,%d]", ns, ne, cs, ce)

	if newData == nil || len(newData.Results) == 0 {
		return cached
	}
	if cached == nil || len(cached.Results) == 0 {
		return newData
	}

	// new range completely supersedes the cached range — replace
	if ns <= cs && ne >= ce {
		return newData
	}

	// disjoint — replace (gap between ranges means no data continuity)
	if ne <= cs || ns >= ce {
		return newData
	}

	// partial overlap: merge timeseries by label fingerprint
	queryTS := newData.Results[0].Timeseries
	cachedTS := cached.Results[0].Timeseries

	// index cached series by fingerprint
	fpIndex := make(map[string]int, len(cachedTS))
	for i, ts := range cachedTS {
		fpIndex[labelFingerprint(ts.Labels)] = i
	}

	// deep-copy all cached series; matched ones get their Samples merged below
	mergedTS := make([]*prompb.TimeSeries, len(cachedTS))
	for i, ts := range cachedTS {
		newLabels := make([]prompb.Label, len(ts.Labels))
		copy(newLabels, ts.Labels)
		newSamples := make([]prompb.Sample, len(ts.Samples))
		copy(newSamples, ts.Samples)
		mergedTS[i] = &prompb.TimeSeries{Labels: newLabels, Samples: newSamples}
	}

	var appendTS []*prompb.TimeSeries
	for _, newTS := range queryTS {
		idx, found := fpIndex[labelFingerprint(newTS.Labels)]
		if !found {
			newLabels := make([]prompb.Label, len(newTS.Labels))
			copy(newLabels, newTS.Labels)
			newSamples := make([]prompb.Sample, len(newTS.Samples))
			copy(newSamples, newTS.Samples)
			appendTS = append(appendTS, &prompb.TimeSeries{Labels: newLabels, Samples: newSamples})
			continue
		}
		// mergeSamples returns a fresh allocation — replaces the copied samples above
		mergedTS[idx].Samples = mergeSamples(mergedTS[idx].Samples, newTS.Samples)
	}

	out := &prompb.ReadResponse{Results: []*prompb.QueryResult{{}}}
	out.Results[0].Timeseries = append(mergedTS, appendTS...)
	return out
}

// labelFingerprint builds a stable string key from a []prompb.Label.
// Prometheus guarantees labels arrive sorted; the fast path skips the
// allocation when they are already in order.
func labelFingerprint(lbls []prompb.Label) string {
	if !labelsNeedSort(lbls) {
		return buildFingerprintString(lbls)
	}
	cp := make([]prompb.Label, len(lbls))
	copy(cp, lbls)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Name != cp[j].Name {
			return cp[i].Name < cp[j].Name
		}
		return cp[i].Value < cp[j].Value
	})
	return buildFingerprintString(cp)
}

func labelsNeedSort(lbls []prompb.Label) bool {
	for i := 1; i < len(lbls); i++ {
		if lbls[i].Name < lbls[i-1].Name ||
			(lbls[i].Name == lbls[i-1].Name && lbls[i].Value < lbls[i-1].Value) {
			return true
		}
	}
	return false
}

func buildFingerprintString(lbls []prompb.Label) string {
	var b strings.Builder
	for i := range lbls {
		b.WriteString(lbls[i].Name)
		b.WriteByte('=')
		b.WriteString(lbls[i].Value)
		b.WriteByte(',')
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// promql.Result merge
// ---------------------------------------------------------------------------

// promqlEntry bundles a promql.Result with its original value type.
// Vectors are converted to matrices on store so merge logic is uniform.
type promqlEntry struct {
	result promql.Result
	vType  parser.ValueType
}

// mergePromqlEntry merges newPe (covering [ns,ne]) into cached (covering [cs,ce]).
func mergePromqlEntry(cached promqlEntry, cs, ce int64, newPe promqlEntry, ns, ne int64) promqlEntry {
	if newPe.vType == parser.ValueTypeVector {
		if v, err := newPe.result.Vector(); err == nil {
			newPe.result.Value = vectorToMatrix(&v, ne)
		}
	}

	// disjoint or new range supersedes — replace
	if ne <= cs || ns >= ce || (ns <= cs && ne >= ce) {
		return newPe
	}

	merged, err := mergeMatrices(newPe.result.Value.(promql.Matrix), &cached.result)
	if err != nil {
		return newPe
	}
	return promqlEntry{result: merged, vType: cached.vType}
}

// mergeMatrices merges incoming matrix data into the cached result.
// Returns a fully fresh promql.Result; never aliases cached.
func mergeMatrices(incoming promql.Matrix, cached *promql.Result) (promql.Result, error) {
	cacheMatrix, err := cached.Matrix()
	if err != nil {
		return promql.Result{Err: err}, err
	}

	// deep-copy cached matrix as the base
	result := make(promql.Matrix, len(cacheMatrix))
	for i, s := range cacheMatrix {
		pts := make([]promql.Point, len(s.Points))
		copy(pts, s.Points)
		result[i] = promql.Series{Metric: s.Metric, Points: pts}
	}

	var appendMatrix []promql.Series
	for _, series := range incoming {
		matched := false
		// Use indexed range so mutations to result[i].Points are persisted.
		// A range-copy (for _, s := range result) would silently discard them.
		for i := range result {
			if labels.Equal(result[i].Metric, series.Metric) {
				result[i].Points = mergePoints(result[i].Points, series.Points)
				matched = true
				break
			}
		}
		if !matched {
			appendMatrix = append(appendMatrix, series)
		}
	}
	if len(appendMatrix) > 0 {
		result = append(result, appendMatrix...)
	}
	return promql.Result{Value: result}, nil
}

// vectorToMatrix converts a promql.Vector to a Matrix for uniform storage.
func vectorToMatrix(v *promql.Vector, t int64) promql.Matrix {
	if len(*v) == 0 {
		return promql.Matrix{
			{Metric: nil, Points: []promql.Point{{T: t, V: 0}}},
		}
	}
	out := make(promql.Matrix, len(*v))
	for i, s := range *v {
		out[i] = promql.Series{
			Metric: s.Metric,
			Points: []promql.Point{s.Point},
		}
	}
	return out
}
