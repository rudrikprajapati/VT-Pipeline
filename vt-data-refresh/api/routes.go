package api

import (
	"vt-data-refresh/config"
	"vt-data-refresh/handlers"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB, cfg *config.Config) {

	reportHandler := handlers.NewReportHandler(db, cfg)
	r.GET("/refresh/domains", reportHandler.RefreshDomainsReports)
	r.GET("/refresh/ips", reportHandler.RefereshIPsReports)
}
