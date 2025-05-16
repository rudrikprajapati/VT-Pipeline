package api

import (
	"vt-data-api/config"
	"vt-data-api/handlers"
	"vt-data-api/redis"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) {

	reportHandler := handlers.NewReportHandler(db, redisClient, cfg)
	r.GET("/report/:id", reportHandler.GetReport)
}
