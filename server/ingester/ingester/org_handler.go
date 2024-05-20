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

package ingester

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/prometheus"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

var CleanDatabaseList = []string{
	"application_log", "deepflow_system", "event", "ext_metrics",
	"flow_log", "flow_metrics", "flow_tag",
	"profile", "prometheus"}

type OrgHandler struct {
	cfg        *config.Config
	promHander *prometheus.PrometheusHandler
}

func NewOrgHandler(cfg *config.Config) *OrgHandler {
	return &OrgHandler{
		cfg: cfg,
	}
}

func (o *OrgHandler) SetPromHandler(promHandler *prometheus.PrometheusHandler) {
	o.promHander = promHandler
}

func (o *OrgHandler) DropOrg(orgId uint16) error {
	log.Info("drop org id:", orgId)
	o.dropOrgCaches(orgId)
	return o.dropOrgDatabase(orgId)
}

// FIXME: After clearing the Org data, if the same Org ID is created again later, data writing will fail. You can restart deepflow-server to solve it.
func (o *OrgHandler) dropOrgDatabase(orgId uint16) error {
	if ckdb.IsDefaultOrgID(orgId) {
		return fmt.Errorf("can not drop default org id: %d", orgId)
	}
	conns, err := common.NewCKConnections(o.cfg.CKDB.ActualAddrs, o.cfg.CKDBAuth.Username, o.cfg.CKDBAuth.Password)
	if err != nil {
		return err
	}
	defer conns.Close()

	for _, db := range CleanDatabaseList {
		sql := fmt.Sprintf("DROP DATABASE IF EXISTS %s", ckdb.OrgDatabasePrefix(orgId)+db)
		_, err := conns.ExecParallel(sql)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *OrgHandler) dropOrgCaches(orgId uint16) {
	if o.promHander == nil {
		return
	}
	o.promHander.DropOrg(orgId)
}
