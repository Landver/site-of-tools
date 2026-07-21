// Package site: serves apex host corpberry.com — portfolio landing page +
// tools index.
package site

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Tools is the single catalog of tools, shared by apex tools index + header's
// Tools dropdown (wired as template func in main). Add new tools here → both
// index + nav pick them up.
func Tools(cfg platform.Config) []platform.Tool {
	return []platform.Tool{
		{
			Name: "IP Tools",
			Desc: "Look up geolocation, ASN, and proxy/VPN for any IP; inspect your own connection (live IPv6 check included); and calculate subnets with the CIDR tool.",
			URL:  cfg.URL("ip"),
		},
		{
			Name: "Bot check",
			Desc: "Score how much your browser looks like a human vs. an automated bot: client fingerprint signals cross-checked against your connection's headers and IP reputation, with a transparent per-signal breakdown.",
			URL:  cfg.URL("botcheck"),
		},
	}
}

// Register wires apex routes onto e.
func Register(e *echo.Echo, cfg platform.Config) {
	e.GET("/", func(c *echo.Context) error {
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Tools": Tools(cfg),
		}
		// No htmx fragment on apex → same template for page + fragment.
		return platform.Respond(c, http.StatusOK, data, "site/home", "site/home")
	})
}
