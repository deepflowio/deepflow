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

func TestChCustomBizService_generateNewData(t *testing.T) {
	tests := []struct {
		name                 string
		dfWebServiceEnabled  bool
		mockResponse         string
		mockStatusCode       int
		expectedItems        int
		expectedError        bool
		expectedServiceNames []string
	}{
		{
			name:                "DFWebService disabled",
			dfWebServiceEnabled: false,
			mockResponse:        "",
			mockStatusCode:      200,
			expectedItems:       0,
			expectedError:       false,
		},
		{
			name:                "successful response with custom biz services",
			dfWebServiceEnabled: true,
			mockResponse: `{
				"DATA": [
					{
						"NAME": "test-biz",
						"TYPE": 3,
						"team_id": 1,
						"svcs": [
							{
								"ID": 100,
								"NAME": "service1"
							},
							{
								"ID": 101,
								"NAME": "service2"
							}
						]
					},
					{
						"NAME": "other-biz",
						"TYPE": 1,
						"team_id": 2,
						"svcs": [
							{
								"ID": 102,
								"NAME": "service3"
							}
						]
					}
				]
			}`,
			mockStatusCode:       200,
			expectedItems:        2,
			expectedError:        false,
			expectedServiceNames: []string{"test-biz/service1", "test-biz/service2"},
		},
		{
			name:                "empty response",
			dfWebServiceEnabled: true,
			mockResponse:        `{"DATA": []}`,
			mockStatusCode:      200,
			expectedItems:       0,
			expectedError:       false,
		},
		{
			name:                "server error",
			dfWebServiceEnabled: true,
			mockResponse:        "",
			mockStatusCode:      500,
			expectedItems:       0,
			expectedError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.mockStatusCode != 200 {
					w.WriteHeader(tt.mockStatusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.mockResponse)
			}))
			defer mockServer.Close()

			// Parse mock server URL
			mockURL := mockServer.URL
			mockHost := mockURL[7:] // remove "http://"
			hostPort := mockHost
			host := "localhost"
			port := 8080
			if mockServer.Listener != nil {
				port = mockServer.Listener.Addr().(*net.TCPAddr).Port
			}

			// Create test instance
			resourceTypeToIconID := map[IconKey]int{
				{NodeType: RESOURCE_TYPE_CUSTOM_BIZ_SERVICE}: 1,
			}
			service := NewChCustomBizService(resourceTypeToIconID)

			// Setup config
			cfg := config.ControllerConfig{
				DFWebService: config.DFWebService{
					Enabled: tt.dfWebServiceEnabled,
					Host:    host,
					Port:    port,
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

				// Verify service names if provided
				if len(tt.expectedServiceNames) > 0 {
					serviceNames := make([]string, 0, len(result))
					for _, item := range result {
						serviceNames = append(serviceNames, item.Name)
					}
					for _, expectedName := range tt.expectedServiceNames {
						assert.Contains(t, serviceNames, expectedName)
					}
				}

				// Verify all items have correct icon ID
				for _, item := range result {
					assert.Equal(t, 1, item.IconID)
					assert.NotEmpty(t, item.Name)
					assert.Greater(t, item.ID, 0)
				}
			}
		})
	}
}

func TestChCustomBizService_generateKey(t *testing.T) {
	service := &ChCustomBizService{}

	testItem := metadbmodel.ChCustomBizService{
		ID:     123,
		Name:   "test-service",
		IconID: 1,
	}

	key := service.generateKey(testItem)
	assert.Equal(t, IDKey{ID: 123}, key)
}

func TestChCustomBizService_generateUpdateInfo(t *testing.T) {
	service := &ChCustomBizService{}

	tests := []struct {
		name           string
		oldItem        metadbmodel.ChCustomBizService
		newItem        metadbmodel.ChCustomBizService
		expectedUpdate bool
		expectedFields map[string]interface{}
	}{
		{
			name: "no changes",
			oldItem: metadbmodel.ChCustomBizService{
				ID:   1,
				Name: "test-service",
			},
			newItem: metadbmodel.ChCustomBizService{
				ID:   1,
				Name: "test-service",
			},
			expectedUpdate: false,
		},
		{
			name: "name changed",
			oldItem: metadbmodel.ChCustomBizService{
				ID:   1,
				Name: "old-service",
			},
			newItem: metadbmodel.ChCustomBizService{
				ID:   1,
				Name: "new-service",
			},
			expectedUpdate: true,
			expectedFields: map[string]interface{}{
				"name": "new-service",
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

func TestNewChCustomBizService(t *testing.T) {
	resourceTypeToIconID := map[IconKey]int{
		{NodeType: RESOURCE_TYPE_CUSTOM_BIZ_SERVICE}: 42,
	}

	service := NewChCustomBizService(resourceTypeToIconID)

	require.NotNil(t, service)
	assert.Equal(t, RESOURCE_TYPE_CH_CUSTOM_BIZ_SERVICE, service.resourceTypeName)
	assert.Equal(t, resourceTypeToIconID, service.resourceTypeToIconID)
	assert.Equal(t, service, service.updaterDG)
}
