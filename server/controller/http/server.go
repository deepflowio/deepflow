/**
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

package http

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	"github.com/deepflowio/deepflow/server/controller/http/router"
	"github.com/deepflowio/deepflow/server/controller/http/router/configuration"
	"github.com/deepflowio/deepflow/server/controller/http/router/resource"
	"github.com/deepflowio/deepflow/server/controller/manager"
	"github.com/deepflowio/deepflow/server/controller/monitor"
	trouter "github.com/deepflowio/deepflow/server/controller/trisolaris/server/http"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logging.MustGetLogger("http")

type Registrant interface {
	RegisterTo(*gin.Engine)
}

type Server struct {
	engine           *gin.Engine
	controllerConfig *config.ControllerConfig

	controllerChecker *monitor.ControllerCheck
	analyzerChecker   *monitor.AnalyzerCheck
	manager           *manager.Manager
	genesis           *genesis.Genesis
}

func NewServer(logFile string, cfg *config.ControllerConfig) *Server {
	s := &Server{controllerConfig: cfg}

	ginLogFile, _ := os.OpenFile(logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	gin.DefaultWriter = io.MultiWriter(ginLogFile, os.Stdout)

	g := gin.New()
	g.Use(gin.Recovery())
	g.Use(gin.LoggerWithFormatter(logger.GinLogFormat))
	s.engine = g
	return s
}

func (s *Server) Start() {
	router.NewHealth().RegisterTo(s.engine)
	go func() {
		if err := s.engine.Run(fmt.Sprintf(":%d", s.controllerConfig.ListenPort)); err != nil {
			log.Errorf("startup service failed, err:%v\n", err)
			time.Sleep(time.Second)
			os.Exit(0)
		}
	}()
}

func (s *Server) SetControllerChecker(cc *monitor.ControllerCheck) {
	s.controllerChecker = cc
}

func (s *Server) SetAnalyzerChecker(ac *monitor.AnalyzerCheck) {
	s.analyzerChecker = ac
}

func (s *Server) SetManager(m *manager.Manager) {
	s.manager = m
}

func (s *Server) SetGenesis(g *genesis.Genesis) {
	s.genesis = g
}

func (s *Server) RegisterRouters() {
	for _, i := range []Registrant{
		router.NewElection(),
		router.NewDebug(s.manager, s.genesis),
		router.NewController(s.controllerConfig, s.controllerChecker),
		router.NewAnalyzer(s.controllerConfig, s.analyzerChecker),
		router.NewVtap(),
		router.NewVtapGroup(s.controllerConfig),
		router.NewDataSource(s.controllerConfig),
		router.NewVTapGroupConfig(),
		router.NewVTapInterface(),
		configuration.NewConfiguration(),
		router.NewVtapRepo(),
		router.NewPlugin(),

		// resource
		resource.NewTask(),
		resource.NewDomain(s.controllerConfig),
		resource.NewAZ(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit, s.controllerConfig.DFWebService),
		resource.NewRegion(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit, s.controllerConfig.DFWebService),
		resource.NewHost(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewVM(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewVInterface(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewVPC(),
		resource.NewSecurityGroup(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit),
		resource.NewSecurityGroupRule(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit),
		resource.NewNATGateway(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit),
		resource.NewNATRule(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit),
		resource.NewLB(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewLBListener(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewLBRule(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPeerConnection(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit),
		resource.NewCEN(s.controllerConfig.HTTPCfg, s.controllerConfig.FPermit),
		resource.NewProcess(s.controllerConfig.RedisCfg),
		resource.NewPod(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodGroup(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodGroupPort(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodReplicaSet(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodService(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodServicePort(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodIngress(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodIngressRule(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodNode(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
		resource.NewPodCluster(s.controllerConfig.HTTPCfg, s.controllerConfig.RedisCfg, s.controllerConfig.FPermit),
	} {
		i.RegisterTo(s.engine)
	}
	trouter.RegisterTo(s.engine)
}
