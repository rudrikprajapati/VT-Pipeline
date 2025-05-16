package handlers

import (
	"net/http"

	"vt-data-refresh/config"
	"vt-data-refresh/services"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// ReportHandler handles report requests for domains and IP addresses
type ReportHandler struct {
	db  *sqlx.DB
	cfg *config.Config
}

// NewReportHandler creates a new ReportHandler instance
func NewReportHandler(db *sqlx.DB, cfg *config.Config) *ReportHandler {
	return &ReportHandler{
		db:  db,
		cfg: cfg,
	}
}

// GetReport handles the GET request for reports
func (h *ReportHandler) RefreshDomainsReports(c *gin.Context) {
	domains := []string{
		"google.com",
		"youtube.com",
		"facebook.com",
		"amazon.com",
		"twitter.com",
		"instagram.com",
		"linkedin.com",
		"wikipedia.org",
		"yahoo.com",
		"reddit.com",
		"netflix.com",
		"microsoft.com",
		"apple.com",
		"tiktok.com",
		"ebay.com",
		"pinterest.com",
		"spotify.com",
		"adobe.com",
		"wordpress.com",
		"tumblr.com",
		"flickr.com",
		"vimeo.com",
		"dropbox.com",
		"slack.com",
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"stackoverflow.com",
		"quora.com",
		"medium.com",
		"nytimes.com",
		"cnn.com",
		"bbc.com",
		"forbes.com",
		"bloomberg.com",
		"wsj.com",
		"theguardian.com",
		"reuters.com",
		"huffpost.com",
		"buzzfeed.com",
		"espn.com",
		"nfl.com",
		"nba.com",
		"mlb.com",
		"nhl.com",
		"fifa.com",
		"olympics.com",
		"airbnb.com",
		"uber.com",
		"lyft.com",
		"booking.com",
		"expedia.com",
		"tripadvisor.com",
		"paypal.com",
		"stripe.com",
		"squareup.com",
		"shopify.com",
		"etsy.com",
		"alibaba.com",
		"rakuten.com",
		"jd.com",
		"walmart.com",
		"target.com",
		"bestbuy.com",
		"costco.com",
		"ikea.com",
		"nike.com",
		"adidas.com",
		"underarmour.com",
		"patagonia.com",
		"tesla.com",
		"spacex.com",
		"intel.com",
		"amd.com",
		"nvidia.com",
		"oracle.com",
		"salesforce.com",
		"sap.com",
		"ibm.com",
		"hp.com",
		"dell.com",
		"cisco.com",
		"zoom.us",
		"skype.com",
		"discord.com",
		"twitch.tv",
		"steamcommunity.com",
		"epicgames.com",
		"playstation.com",
		"xbox.com",
		"nintendo.com",
		"coursera.org",
		"edx.org",
		"khanacademy.org",
		"duolingo.com",
		"weather.com",
		"accuweather.com",
		"webmd.com",
		"mayoclinic.org",
	}

	domains20 := domains[:20]
	report, err := services.FetchDomainVTReport(domains20, "domains", h.db, h.cfg)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

func (h *ReportHandler) RefereshIPsReports(c *gin.Context) {
	ips := []string{
		"8.8.8.8",         // Google DNS (benign)
		"1.1.1.1",         // Cloudflare DNS (benign)
		"206.54.170.81",   // Historical example from VirusTotal blog[](https://blog.virustotal.com/2020/02/uncovering-threat-infrastructure-via.html)
		"185.220.101.134", // Example from threat intelligence (e.g., URLhaus)
		"4.2.2.2",         // Level3 DNS (benign)
		"9.9.9.9",         // Quad9 DNS (benign)
		"31.139.365.245",  // Example from VirusTotal docs[](https://virustotal.readme.io/reference/ip-object)
		"107.23.246.142",  // Example from VirusTotal blog (file.io)[](https://blog.virustotal.com/2023/02/monitoring-infrastructure.html)
		"34.197.10.85",    // Example from VirusTotal blog (file.io)[](https://blog.virustotal.com/2023/02/monitoring-infrastructure.html)
		"173.194.0.1",     // Google-related IP range example[](https://blog.virustotal.com/2023/02/monitoring-infrastructure.html)
		"192.168.1.1",     // Common router IP (not public, included for testing)
		"104.16.249.249",  // Cloudflare-related IP
		"198.51.100.1",    // TEST-NET-2 (documentation, safe)
		"203.0.113.1",     // TEST-NET-3 (documentation, safe)
		"162.125.248.18",  // Example from VirusTotal blog (content search)[](https://blog.virustotal.com/2023/02/monitoring-infrastructure.html)
		"45.79.147.101",   // Historical threat feed example
		"185.243.115.230", // Historical threat feed example
		"91.219.238.117",  // Historical threat feed example
		"77.88.55.66",     // Yandex DNS (benign)
		"208.67.222.222",  // OpenDNS (benign)
		// Additional public IPs to reach 100 (curated from public ranges)
		"104.244.42.1",  // Twitter-related IP
		"142.250.190.1", // Google-related IP
		"172.217.0.1",   // Google-related IP
		"151.101.1.1",   // Fastly CDN
		"23.185.0.1",    // Pantheon hosting
		"198.41.128.1",  // Cloudflare-related IP
		"216.58.192.1",  // Google-related IP
		"93.184.216.1",  // Edgecast CDN
		"52.84.0.1",     // AWS CloudFront
		"13.35.0.1",     // AWS-related IP
		"54.230.0.1",    // AWS-related IP
		"18.64.0.1",     // AWS-related IP
		"99.84.0.1",     // AWS-related IP
		"108.138.0.1",   // AWS-related IP
		"143.204.0.1",   // AWS-related IP
		"204.246.160.1", // Akamai-related IP
		"23.32.0.1",     // Akamai-related IP
		"72.246.0.1",    // Akamai-related IP
		"184.24.0.1",    // Akamai-related IP
		"2.16.0.1",      // Akamai-related IP
		"88.221.0.1",    // Akamai-related IP
		"104.64.0.1",    // Akamai-related IP
		"173.222.0.1",   // Akamai-related IP
		"184.50.0.1",    // Akamai-related IP
		"209.200.0.1",   // Akamai-related IP
		"69.192.0.1",    // Akamai-related IP
		"23.192.0.1",    // Akamai-related IP
		"96.6.0.1",      // Akamai-related IP
		"104.90.0.1",    // Akamai-related IP
		"23.40.0.1",     // Akamai-related IP
		"104.123.0.1",   // Akamai-related IP
		"23.48.0.1",     // Akamai-related IP
		"104.124.0.1",   // Akamai-related IP
		"23.56.0.1",     // Akamai-related IP
		"104.125.0.1",   // Akamai-related IP
		"23.64.0.1",     // Akamai-related IP
		"104.126.0.1",   // Akamai-related IP
		"23.72.0.1",     // Akamai-related IP
		"104.127.0.1",   // Akamai-related IP
		"23.80.0.1",     // Akamai-related IP
		"104.128.0.1",   // Akamai-related IP
		"23.88.0.1",     // Akamai-related IP
		"104.129.0.1",   // Akamai-related IP
		"23.96.0.1",     // Microsoft Azure-related IP
		"13.64.0.1",     // Microsoft Azure-related IP
		"40.64.0.1",     // Microsoft Azure-related IP
		"52.224.0.1",    // Microsoft Azure-related IP
		"20.34.0.1",     // Microsoft Azure-related IP
		"104.40.0.1",    // Microsoft Azure-related IP
		"137.116.0.1",   // Microsoft Azure-related IP
		"168.61.0.1",    // Microsoft Azure-related IP
		"191.232.0.1",   // Microsoft Azure-related IP
		"65.52.0.1",     // Microsoft Azure-related IP
		"104.208.0.1",   // Microsoft Azure-related IP
		"23.100.0.1",    // Microsoft Azure-related IP
		"104.43.0.1",    // Microsoft Azure-related IP
		"104.44.0.1",    // Microsoft Azure-related IP
		"104.45.0.1",    // Microsoft Azure-related IP
		"104.46.0.1",    // Microsoft Azure-related IP
		"104.47.0.1",    // Microsoft Azure-related IP
		"104.210.0.1",   // Microsoft Azure-related IP
		"104.211.0.1",   // Microsoft Azure-related IP
		"104.212.0.1",   // Microsoft Azure-related IP
		"104.213.0.1",   // Microsoft Azure-related IP
		"104.214.0.1",   // Microsoft Azure-related IP
		"104.215.0.1",   // Microsoft Azure-related IP
		"13.66.0.1",     // Microsoft Azure-related IP
		"13.67.0.1",     // Microsoft Azure-related IP
		"13.68.0.1",     // Microsoft Azure-related IP
		"13.69.0.1",     // Microsoft Azure-related IP
		"13.70.0.1",     // Microsoft Azure-related IP
		"13.71.0.1",     // Microsoft Azure-related IP
		"13.72.0.1",     // Microsoft Azure-related IP
		"13.73.0.1",     // Microsoft Azure-related IP
		"13.74.0.1",     // Microsoft Azure-related IP
		"13.75.0.1",     // Microsoft Azure-related IP
	}

	ips20 := ips[:20]
	report, err := services.FetchIPReport(ips20, "ip_addresses", h.db, h.cfg)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}
