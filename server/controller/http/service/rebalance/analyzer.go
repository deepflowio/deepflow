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

package rebalance

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// //go:generate mockgen -source=analyzer.go -destination=./mocks/mock_analyzer.go -package=mocks DB
type DB interface {
	Get() error
}

type DBInfo struct {
	AZs             []mysql.AZ
	Analyzers       []mysql.Analyzer
	AZAnalyzerConns []mysql.AZAnalyzerConnection
	VTaps           []mysql.VTap

	// get query data
	Controllers       []mysql.Controller
	AZControllerConns []mysql.AZControllerConnection
}

type AnalyzerInfo struct {
	dbInfo                    *DBInfo
	regionToVTapNameToTraffic map[string]map[string]int64

	db    DB
	query Querier
}

func NewAnalyzerInfo() *AnalyzerInfo {
	return &AnalyzerInfo{
		dbInfo: &DBInfo{},
		query:  &Query{},
	}
}

func (r *DBInfo) Get(db *mysql.DB) error {
	if err := db.Find(&r.AZs).Error; err != nil {
		return err
	}
	if err := db.Find(&r.Analyzers).Error; err != nil {
		return err
	}
	if err := db.Find(&r.AZAnalyzerConns).Error; err != nil {
		return err
	}
	if err := db.Where("type != ?", common.VTAP_TYPE_TUNNEL_DECAPSULATION).Find(&r.VTaps).Error; err != nil {
		return err
	}

	if err := db.Find(&r.Controllers).Error; err != nil {
		return err
	}
	if err := db.Find(&r.AZControllerConns).Error; err != nil {
		return err
	}
	return nil
}

func GetAZToAnalyzers(azAnalyzerConns []mysql.AZAnalyzerConnection, regionToAZLcuuids map[string][]string,
	ipToAnalyzer map[string]*mysql.Analyzer) map[string][]*mysql.Analyzer {

	azToAnalyzers := make(map[string][]*mysql.Analyzer)
	for _, conn := range azAnalyzerConns {
		if conn.AZ == "ALL" {
			if azLcuuids, ok := regionToAZLcuuids[conn.Region]; ok {
				for _, azLcuuid := range azLcuuids {
					if analyzer, ok := ipToAnalyzer[conn.AnalyzerIP]; ok {
						azToAnalyzers[azLcuuid] = append(
							azToAnalyzers[azLcuuid], analyzer,
						)
					}
				}
			}
		} else {
			if analyzer, ok := ipToAnalyzer[conn.AnalyzerIP]; ok {
				azToAnalyzers[conn.AZ] = append(azToAnalyzers[conn.AZ], analyzer)
			}
		}
	}
	return azToAnalyzers
}
