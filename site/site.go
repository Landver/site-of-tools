// Package site serves the apex host corpberry.com: the portfolio landing page
// and an index of the tools.
package site

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

type tool struct {
	Name string
	Desc string
	URL  string
}

// Register wires the apex routes onto e.
func Register(e *echo.Echo, cfg platform.Config) {
	tools := []tool{
		{
			Name: "IP Toolkit",
			Desc: "Geolocation, network (ASN), and proxy/VPN detection for any IP, plus a live IPv6 connectivity check.",
			URL:  cfg.URL("ip"),
		},
	}

	e.GET("/", func(c *echo.Context) error {
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Tools": tools,
		}
		// No htmx fragment on the apex; same template for page and fragment.
		return platform.Respond(c, http.StatusOK, data, "site/home", "site/home")
	})
}
