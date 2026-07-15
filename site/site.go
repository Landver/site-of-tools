// Package site serves the apex host corpberry.com: the portfolio landing page
// and an index of the tools.
package site

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Tools is the single catalog of tools, shared by the apex tools index and the
// header's Tools dropdown (wired as a template func in main). Add new tools here
// and both the index and the nav pick them up.
func Tools(cfg platform.Config) []platform.Tool {
	return []platform.Tool{
		{
			Name: "IP Tools",
			Desc: "Geolocation, network (ASN), and proxy/VPN detection for any IP, plus a live IPv6 connectivity check.",
			URL:  cfg.URL("ip"),
		},
	}
}

// Register wires the apex routes onto e.
func Register(e *echo.Echo, cfg platform.Config) {
	e.GET("/", func(c *echo.Context) error {
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Tools": Tools(cfg),
		}
		// No htmx fragment on the apex; same template for page and fragment.
		return platform.Respond(c, http.StatusOK, data, "site/home", "site/home")
	})
}
