/*
 * Copyright (c) 2022 Yunshan Networks
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
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"

	"github.com/metaflowys/metaflow/server/controller/trisolaris/config"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/utils"
)

func Run(ctx context.Context, cfg *config.Config) {
	mux := SetupMux(cfg)

	srv := &http.Server{
		Addr:    net.JoinHostPort("", cfg.ListenPort),
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Info("listen:", err)
		}
	}()

	wg := utils.GetWaitGroupInCtx(ctx)
	wg.Add(1)
	defer wg.Done()
	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("http server shutdown err: %+v", err)
		return
	}
	log.Info("http server shutdown")
}

func SetupMux(cfg *config.Config) http.Handler {
	if cfg.LogLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	mux := gin.New()
	mux.Use(RequestLoggerMiddleware)

	pprof.Register(mux) // default is "debug/pprof"
	RegistRouter(mux)

	return mux
}
