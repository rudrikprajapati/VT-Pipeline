package api

import (
	"net/http"
	"vt-data-api/config"
	"vt-data-api/handlers"
	"vt-data-api/redis"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) {
	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	reportHandler := handlers.NewReportHandler(db, redisClient, cfg)
	r.GET("/report/:id", reportHandler.GetReport)
}
