package mailtools

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

const (
	dmarcDesc = "Zero-knowledge DMARC aggregate report (RUA XML.GZ) visualizer and alignment auditor. Sensitive email telemetry stays entirely inside your browser."
	bimiDesc  = "Validate Brand Indicators for Message Identification (BIMI) SVG Tiny P/S logos and auto-fix formatting errors for Gmail and Apple Mail."
	arcDesc   = "Analyze Authenticated Received Chain (RFC 8617) headers to diagnose forwarding breakages and verify SPF/DKIM survivability."
)

// Limits sets per-IP request bounds for mailtools routes.
type Limits struct {
	Pure  platform.Limiter
	Heavy platform.Limiter
}

func NewLimits() *Limits {
	return &Limits{
		Pure:  platform.NewLimiter(10, 50),
		Heavy: platform.NewLimiter(2, 10),
	}
}

type handler struct {
	base string
	lim  *Limits
}

// Register mounts mailtools routes onto the Echo router.
func Register(e *echo.Echo, base string, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{base: base, lim: lim}

	pure := platform.RateLimit(lim.Pure, nil, limited)
	heavy := platform.RateLimit(lim.Heavy, nil, limited)

	e.GET("/", h.index, pure)
	e.GET("/dmarc", h.dmarc, pure)
	e.POST("/dmarc", h.dmarc, heavy)
	e.POST("/dmarc/parse", h.dmarcParse, heavy)

	e.GET("/bimi", h.bimi, pure)
	e.POST("/bimi", h.bimi, pure)
	e.POST("/bimi/fix", h.bimiFix, pure)

	e.GET("/arc", h.arc, pure)
	e.POST("/arc", h.arc, pure)
	e.POST("/arc/parse", h.arcParse, pure)
}

func (h *handler) vm(active, heading, desc string) map[string]any {
	return map[string]any{
		"Active":  active,
		"Title":   heading + " — Mail Tools",
		"Desc":    desc,
		"Heading": heading,
		"Base":    h.base,
	}
}

func (h *handler) index(c *echo.Context) error {
	return c.Redirect(http.StatusMovedPermanently, "/dmarc")
}

func (h *handler) dmarc(c *echo.Context) error {
	vm := h.vm("dmarc", "DMARC Report Visualizer", dmarcDesc)

	if c.Request().Method == http.MethodGet {
		return platform.Reply(c, http.StatusOK, nil, vm, "mail/dmarc", "mail/dmarc-result")
	}

	// Handle uploaded file or pasted XML
	var r io.Reader
	file, err := c.FormFile("report_file")
	if err == nil {
		f, err := file.Open()
		if err != nil {
			return h.badRequest(c, vm, err, "mail/dmarc")
		}
		defer f.Close()
		r = f
	} else {
		pasted := strings.TrimSpace(c.FormValue("xml"))
		if pasted == "" {
			return h.badRequest(c, vm, errors.New("please upload a .xml or .xml.gz DMARC report, or paste raw XML"), "mail/dmarc")
		}
		r = strings.NewReader(pasted)
	}

	rep, err := ParseDMARCReport(r)
	if err != nil {
		return h.badRequest(c, vm, err, "mail/dmarc")
	}

	vm["Result"] = rep
	return platform.Reply(c, http.StatusOK, rep, vm, "mail/dmarc", "mail/dmarc-result")
}

func (h *handler) dmarcParse(c *echo.Context) error {
	var r io.Reader
	file, err := c.FormFile("file")
	if err == nil {
		f, err := file.Open()
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		defer f.Close()
		r = f
	} else {
		pasted := strings.TrimSpace(c.FormValue("xml"))
		if pasted == "" {
			// Try reading raw request body
			r = c.Request().Body
		} else {
			r = strings.NewReader(pasted)
		}
	}

	rep, err := ParseDMARCReport(r)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, rep)
}

func (h *handler) bimi(c *echo.Context) error {
	vm := h.vm("bimi", "BIMI SVG Validator & Auto-Fixer", bimiDesc)

	if c.Request().Method == http.MethodGet {
		return platform.Reply(c, http.StatusOK, nil, vm, "mail/bimi", "mail/bimi-result")
	}

	var rawSVG string
	file, err := c.FormFile("svg_file")
	if err == nil {
		f, err := file.Open()
		if err != nil {
			return h.badRequest(c, vm, err, "mail/bimi")
		}
		defer f.Close()
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, f); err != nil {
			return h.badRequest(c, vm, err, "mail/bimi")
		}
		rawSVG = buf.String()
	} else {
		rawSVG = strings.TrimSpace(c.FormValue("svg"))
	}

	if rawSVG == "" {
		return h.badRequest(c, vm, errors.New("no SVG content provided"), "mail/bimi")
	}

	val, err := ValidateBIMI(rawSVG)
	if err != nil {
		return h.badRequest(c, vm, err, "mail/bimi")
	}

	vm["Result"] = val
	vm["RawSVG"] = rawSVG
	return platform.Reply(c, http.StatusOK, val, vm, "mail/bimi", "mail/bimi-result")
}

func (h *handler) bimiFix(c *echo.Context) error {
	rawSVG := strings.TrimSpace(c.FormValue("svg"))
	if rawSVG == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "no SVG provided"})
	}
	fixed, err := AutoFixBIMI(rawSVG)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if platform.WantsJSON(c) {
		return c.JSON(http.StatusOK, map[string]string{"svg": fixed})
	}
	c.Response().Header().Set("Content-Type", "image/svg+xml")
	c.Response().Header().Set("Content-Disposition", "attachment; filename=\"bimi-logo.svg\"")
	return c.String(http.StatusOK, fixed)
}

func (h *handler) arc(c *echo.Context) error {
	vm := h.vm("arc", "ARC Header Trace Analyzer", arcDesc)

	if c.Request().Method == http.MethodGet {
		return platform.Reply(c, http.StatusOK, nil, vm, "mail/arc", "mail/arc-result")
	}

	headers := strings.TrimSpace(c.FormValue("headers"))
	if headers == "" {
		return h.badRequest(c, vm, errors.New("please paste email headers containing ARC-Seal and ARC-Authentication-Results"), "mail/arc")
	}

	arc, err := AnalyzeARC(headers)
	if err != nil {
		return h.badRequest(c, vm, err, "mail/arc")
	}

	vm["Result"] = arc
	vm["Headers"] = headers
	return platform.Reply(c, http.StatusOK, arc, vm, "mail/arc", "mail/arc-result")
}

func (h *handler) arcParse(c *echo.Context) error {
	headers := strings.TrimSpace(c.FormValue("headers"))
	if headers == "" {
		body, _ := io.ReadAll(c.Request().Body)
		headers = strings.TrimSpace(string(body))
	}
	if headers == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "no headers provided"})
	}
	arc, err := AnalyzeARC(headers)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, arc)
}

func (h *handler) badRequest(c *echo.Context, vm map[string]any, err error, page string) error {
	vm["Error"] = err.Error()
	return platform.Reply(c, http.StatusBadRequest, map[string]string{"error": err.Error()}, vm, page, "mail/error")
}

func limited(c *echo.Context) error {
	const msg = platform.LimitedMessage
	return platform.Reply(c, http.StatusTooManyRequests,
		map[string]string{"error": msg},
		map[string]any{"Title": "Slow down — Mail Tools", "Desc": msg, "Error": msg, "Active": ""},
		"mail/error", "mail/error")
}

// SitemapPages lists the public tool routes on mail.corpberry.com.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{
		{Path: "/dmarc"},
		{Path: "/bimi"},
		{Path: "/arc"},
	}, nil
}
