package api

import (
	"vt-data-refresh/config"
	"vt-data-refresh/handlers"
	"vt-data-refresh/redis"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) {

	reportHandler := handlers.NewReportHandler(db, redisClient, cfg)
	r.GET("/refresh/domains", reportHandler.RefreshDomainsReports)
	r.GET("/refresh/ips", reportHandler.RefereshIPsReports)
}
