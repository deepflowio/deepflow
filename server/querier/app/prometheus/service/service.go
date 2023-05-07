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
	"context"

	"github.com/prometheus/prometheus/prompb"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
)

func PromRemoteReadService(req *prompb.ReadRequest, ctx context.Context) (resp *prompb.ReadResponse, err error) {
	return promReaderExecute(req, ctx)
}

func PromInstantQueryService(args *model.PromQueryParams, ctx context.Context) (*model.PromQueryResponse, error) {
	return promQueryExecute(args, ctx)
}

func PromRangeQueryService(args *model.PromQueryParams, ctx context.Context) (*model.PromQueryResponse, error) {
	return promQueryRangeExecute(args, ctx)
}

func PromLabelValuesService(args *model.PromMetaParams, ctx context.Context) (*model.PromQueryResponse, error) {
	return getTagValues(args, ctx)
}

func PromSeriesQueryService(args *model.PromQueryParams, ctx context.Context) (*model.PromQueryResponse, error) {
	return series(args, ctx)
}
