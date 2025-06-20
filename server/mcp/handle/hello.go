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

package handle

import (
	"context"

	"github.com/baidubce/bce-sdk-go/util/log"
	"github.com/deepflowio/deepflow/server/controller/common"

	"github.com/mark3labs/mcp-go/mcp"
)

func RequestToURL(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url := request.GetString("url", "http://warrant:20413/licensedata")
	respJson, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		log.Errorf("request url (%s) failed:", url)
		return nil, err
	}

	prettyResp, err := respJson.EncodePretty()
	if err != nil {
		log.Errorf("encode response json (%v) failed: %s", respJson, err)
		return nil, err
	}

	return mcp.NewToolResultText(string(prettyResp)), nil
}
