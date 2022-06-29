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
