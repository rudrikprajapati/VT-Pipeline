package cron

import (
	"log"
	"net/http"
	"vt-data-refresh/config"

	"github.com/robfig/cron/v3"
)

type CronService struct {
	cfg    *config.Config
	cron   *cron.Cron
	client *http.Client
}

func NewCronService(cfg *config.Config) *CronService {
	return &CronService{
		cfg:    cfg,
		cron:   cron.New(),
		client: &http.Client{},
	}
}

func (s *CronService) Start() {
	s.cron.AddFunc("@every 24h", func() {
		// s.cron.AddFunc("@every 2m", func() {
		s.refreshDomains()
		s.refreshIPs()
	})

	// Start the cron scheduler
	s.cron.Start()
}

func (s *CronService) Stop() {
	s.cron.Stop()
}

func (s *CronService) refreshDomains() {
	resp, err := s.client.Get("http://localhost:" + s.cfg.Server.Port + "/refresh/domains")
	if err != nil {
		log.Printf("Error refreshing domains: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("Domains refresh completed with status: %d", resp.StatusCode)
}

func (s *CronService) refreshIPs() {
	resp, err := s.client.Get("http://localhost:" + s.cfg.Server.Port + "/refresh/ips")
	if err != nil {
		log.Printf("Error refreshing IPs: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("IPs refresh completed with status: %d", resp.StatusCode)
}
