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

package tagrecorder

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

func TestChCustomBizServiceFilter_generateNewData(t *testing.T) {
	tests := []struct {
		name                   string
		dfWebServiceEnabled    bool
		querierJSServiceConfig config.QuerierJSService
		mockDFWebResponse      string
		mockQuerierJSResponse  string
		mockStatusCode         int
		expectedItems          int
		expectedError          bool
	}{
		{
			name:                "DFWebService disabled",
			dfWebServiceEnabled: false,
			mockDFWebResponse:   "",
			mockStatusCode:      200,
			expectedItems:       0,
			expectedError:       false,
		},
		{
			name:                "successful response with filters",
			dfWebServiceEnabled: true,
			querierJSServiceConfig: config.QuerierJSService{
				Host: "localhost",
				Port: 8081,
			},
			mockDFWebResponse: `{
				"DATA": [
					{
						"NAME": "test-biz",
						"TYPE": 3,
						"TABLE_NAME": "flow_log.vtap_flow_edge_port",
						"svcs": [
							{
								"ID": 100,
								"NAME": "service1",
								"SEARCH_PARAMS": {
									"c": [
										{
											"condition": [
												{"type": "tag", "key": "chost", "op": "=", "rsType": "select", "val": 2}
											]
										}
									],
									"s": [
										{
											"condition": [
												{"type": "tag", "key": "pod", "op": "=", "rsType": "select", "val": 3}
											]
										}
									],
									"dual": []
								}
							}
						]
					}
				]
			}`,
			mockQuerierJSResponse: `{
				"DATA": {
					"path": [
						{
							"sql": {
								"QUERY_ID": "R100-client",
								"WHERE": "chost = 2"
							}
						}
					]
				}
			}`,
			mockStatusCode: 200,
			expectedItems:  1,
			expectedError:  false,
		},
		{
			name:                "empty biz data",
			dfWebServiceEnabled: true,
			mockDFWebResponse:   `{"DATA": []}`,
			mockStatusCode:      200,
			expectedItems:       0,
			expectedError:       false,
		},
		{
			name:                "server error",
			dfWebServiceEnabled: true,
			mockDFWebResponse:   "",
			mockStatusCode:      500,
			expectedItems:       0,
			expectedError:       true,
		},
		{
			name:                "invalid table name",
			dfWebServiceEnabled: true,
			mockDFWebResponse: `{
				"DATA": [
					{
						"NAME": "test-biz",
						"TYPE": 3,
						"TABLE_NAME": "invalid_table",
						"svcs": []
					}
				]
			}`,
			mockStatusCode: 200,
			expectedItems:  0,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dfMockServer, querierMockServer *httptest.Server

			// Setup DFWebService mock server
			dfMockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.mockStatusCode != 200 {
					w.WriteHeader(tt.mockStatusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.mockDFWebResponse)
			}))
			defer dfMockServer.Close()

			// Setup QuerierJSService mock server
			querierMockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.mockQuerierJSResponse)
			}))
			defer querierMockServer.Close()

			// Get ports from mock servers
			dfPort := dfMockServer.Listener.Addr().(*net.TCPAddr).Port
			querierPort := querierMockServer.Listener.Addr().(*net.TCPAddr).Port

			// Create test instance
			service := NewChCustomBizServiceFilter()

			// Setup config
			cfg := config.ControllerConfig{
				DFWebService: config.DFWebService{
					Enabled: tt.dfWebServiceEnabled,
					Host:    "localhost",
					Port:    dfPort,
				},
				QuerierJSService: config.QuerierJSService{
					Host: "localhost",
					Port: querierPort,
				},
			}
			service.cfg = cfg

			// Create mock DB
			db := &metadb.DB{
				ORGID:          1,
				LogPrefixORGID: "[ORGID-1]",
			}

			// Execute test
			result, ok := service.generateNewData(db)

			// Assertions
			if tt.expectedError {
				assert.False(t, ok)
				assert.Nil(t, result)
			} else {
				assert.True(t, ok)
				assert.Len(t, result, tt.expectedItems)

				// Verify all items have valid ID
				for _, item := range result {
					assert.Greater(t, item.ID, 0)
				}
			}
		})
	}
}

func TestChCustomBizServiceFilter_generateKey(t *testing.T) {
	service := &ChCustomBizServiceFilter{}

	testItem := metadbmodel.ChCustomBizServiceFilter{
		ID:           123,
		ClientFilter: "client_filter",
		ServerFilter: "server_filter",
	}

	key := service.generateKey(testItem)
	assert.Equal(t, IDKey{ID: 123}, key)
}

func TestChCustomBizServiceFilter_generateUpdateInfo(t *testing.T) {
	service := &ChCustomBizServiceFilter{}

	tests := []struct {
		name           string
		oldItem        metadbmodel.ChCustomBizServiceFilter
		newItem        metadbmodel.ChCustomBizServiceFilter
		expectedUpdate bool
		expectedFields map[string]interface{}
	}{
		{
			name: "no changes",
			oldItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "old_client_filter",
				ServerFilter: "old_server_filter",
			},
			newItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "old_client_filter",
				ServerFilter: "old_server_filter",
			},
			expectedUpdate: false,
		},
		{
			name: "client filter changed",
			oldItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "old_client_filter",
				ServerFilter: "server_filter",
			},
			newItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "new_client_filter",
				ServerFilter: "server_filter",
			},
			expectedUpdate: true,
			expectedFields: map[string]interface{}{
				"client_filter": "new_client_filter",
			},
		},
		{
			name: "server filter changed",
			oldItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "client_filter",
				ServerFilter: "old_server_filter",
			},
			newItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "client_filter",
				ServerFilter: "new_server_filter",
			},
			expectedUpdate: true,
			expectedFields: map[string]interface{}{
				"server_filter": "new_server_filter",
			},
		},
		{
			name: "both filters changed",
			oldItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "old_client_filter",
				ServerFilter: "old_server_filter",
			},
			newItem: metadbmodel.ChCustomBizServiceFilter{
				ID:           1,
				ClientFilter: "new_client_filter",
				ServerFilter: "new_server_filter",
			},
			expectedUpdate: true,
			expectedFields: map[string]interface{}{
				"client_filter": "new_client_filter",
				"server_filter": "new_server_filter",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updateInfo, hasUpdate := service.generateUpdateInfo(tt.oldItem, tt.newItem)

			assert.Equal(t, tt.expectedUpdate, hasUpdate)
			if tt.expectedUpdate {
				assert.NotNil(t, updateInfo)
				for key, expectedValue := range tt.expectedFields {
					assert.Equal(t, expectedValue, updateInfo[key])
				}
			} else {
				assert.Nil(t, updateInfo)
			}
		})
	}
}

func TestNewChCustomBizServiceFilter(t *testing.T) {
	service := NewChCustomBizServiceFilter()

	require.NotNil(t, service)
	assert.Equal(t, RESOURCE_TYPE_CH_CUSTOM_BIZ_SERVICE_FILTER, service.resourceTypeName)
	assert.Equal(t, service, service.updaterDG)
}

func TestConditionItemStructs(t *testing.T) {
	// Test the condition structures used in the filter
	condition := ConditionItem{
		Type:   "tag",
		Key:    "chost",
		Op:     "=",
		RsType: "select",
		Val:    123,
	}

	assert.Equal(t, "tag", condition.Type)
	assert.Equal(t, "chost", condition.Key)
	assert.Equal(t, "=", condition.Op)
	assert.Equal(t, "select", condition.RsType)
	assert.Equal(t, 123, condition.Val)

	resourceSet := ResourceSet{
		ID:        "R100",
		Condition: []ConditionItem{condition},
	}

	assert.Equal(t, "R100", resourceSet.ID)
	assert.Len(t, resourceSet.Condition, 1)

	conditions := Conditions{
		ResourceSets: []ResourceSet{resourceSet},
	}

	assert.Len(t, conditions.ResourceSets, 1)
}
