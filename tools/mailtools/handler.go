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
	maxBIMIPayload = 64 * 1024
	maxARCPayload  = 256 * 1024

	healthDesc     = "All-in-one email deliverability, SEG gateway identification, disposable detection & blacklist audit."
	disposableDesc = "Detect over 10,000+ throwaway, burner, and temporary email domains powered by the canonical disposable-email-domains database."
	classifierDesc = "Classify email domains into corporate business accounts versus personal free consumer webmail (Gmail, Yahoo, Mail.ru, Proton)."
	blacklistDesc  = "Concurrent multi-DNSBL reputation audit querying 15+ global authoritative spam blacklists (Spamhaus, Barracuda, SpamCop, Mailspike) in < 800 ms."
	dmarcDesc      = "Parse and visualize DMARC aggregate XML and gzip reports (RUA) directly in your browser. Inspect SPF/DKIM alignment, IP sources, ESPs, and policy disposition."
	bimiDesc       = "Audit SVG logos against BIMI Tiny P/S requirements and cryptographically validate Verified Mark Certificates (VMC) from DigiCert, GlobalSign, and SSL.com."
	arcDesc        = "Trace and validate Authenticated Received Chain (RFC 8617) headers. Audit multi-hop email forwarding, ARC seals, signatures, and authentication states."
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
	base   string
	guard  *platform.EgressGuard
	store  *Store
	dqsKey string
	lim    *Limits
}

// Register mounts mailtools routes onto the Echo router.
func Register(e *echo.Echo, base string, guard *platform.EgressGuard, store *Store, dqsKey string, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{
		base:   base,
		guard:  guard,
		store:  store,
		dqsKey: dqsKey,
		lim:    lim,
	}

	pure := platform.RateLimit(lim.Pure, nil, limited)
	heavy := platform.RateLimit(lim.Heavy, nil, limited)
	skipEmpty := func(c *echo.Context) bool {
		return formOrQuery(c, "domain", "target", "input", "q") == ""
	}
	heavyAudit := platform.RateLimit(lim.Heavy, skipEmpty, limited)

	e.GET("/", h.health, heavyAudit)
	e.GET("/health", h.health, heavyAudit)
	e.POST("/", h.health, heavyAudit)
	e.POST("/health", h.health, heavyAudit)

	e.GET("/disposable", h.disposable, pure)
	e.POST("/disposable", h.disposable, pure)

	e.GET("/classifier", h.classifier, pure)
	e.POST("/classifier", h.classifier, pure)

	e.GET("/blacklist", h.blacklist, heavyAudit)
	e.POST("/blacklist", h.blacklist, heavyAudit)

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
	canonical := h.base
	if active != "" && active != "index" && active != "/" {
		canonical = h.base + "/" + strings.TrimPrefix(active, "/")
	}
	return map[string]any{
		"Active":    active,
		"Title":     heading + " — Mail Tools",
		"Desc":      desc,
		"Heading":   heading,
		"Base":      h.base,
		"Canonical": canonical,
		"Subdomain": "mail",
	}
}

func formOrQuery(c *echo.Context, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(c.FormValue(k)); v != "" {
			return v
		}
	}
	for _, k := range keys {
		if v := strings.TrimSpace(c.QueryParam(k)); v != "" {
			return v
		}
	}
	return ""
}

func (h *handler) health(c *echo.Context) error {
	vm := h.vm("health", "Domain & Email Intelligence Audit", healthDesc)
	target := formOrQuery(c, "domain", "input")
	if target == "" {
		if c.Request().Method == http.MethodGet {
			return platform.Reply(c, http.StatusOK, nil, vm, "mail/health", "mail/health-result")
		}
		return h.badRequest(c, vm, errors.New("please provide a domain name or email address"), "mail/health")
	}

	vm["Domain"] = target
	report, err := AuditDomainHealth(c.Request().Context(), target, h.guard, h.store, h.dqsKey)
	if err != nil {
		return h.badRequest(c, vm, err, "mail/health")
	}

	vm["Result"] = report
	return platform.Reply(c, http.StatusOK, report, vm, "mail/health", "mail/health-result")
}

func (h *handler) classifyRoute(c *echo.Context, route, heading, desc, emptyErr string) error {
	vm := h.vm(route, heading, desc)
	tmpl := "mail/" + route
	frag := tmpl + "-result"

	input := formOrQuery(c, "input", "domain")
	if input == "" {
		if c.Request().Method == http.MethodGet {
			return platform.Reply(c, http.StatusOK, nil, vm, tmpl, frag)
		}
		return h.badRequest(c, vm, errors.New(emptyErr), tmpl)
	}

	vm["Input"] = input
	res := ActiveClassifier().Classify(input)
	vm["Result"] = res
	return platform.Reply(c, http.StatusOK, res, vm, tmpl, frag)
}

func (h *handler) disposable(c *echo.Context) error {
	return h.classifyRoute(c, "disposable", "Disposable Email & Burner Domain Checker", disposableDesc, "please provide an email or domain to verify")
}

func (h *handler) classifier(c *echo.Context) error {
	return h.classifyRoute(c, "classifier", "Free Webmail vs Corporate Domain Classifier", classifierDesc, "please provide an email or domain to classify")
}

func (h *handler) blacklist(c *echo.Context) error {
	vm := h.vm("blacklist", "Real-Time Multi-DNSBL Reputation Checker", blacklistDesc)
	target := formOrQuery(c, "target", "domain", "ip", "input")
	if target == "" {
		if c.Request().Method == http.MethodGet {
			return platform.Reply(c, http.StatusOK, nil, vm, "mail/blacklist", "mail/blacklist-result")
		}
		return h.badRequest(c, vm, errors.New("please provide an IP address or hostname to audit"), "mail/blacklist")
	}

	vm["Target"] = target

	rep, err := CachedDNSBLAudit(c.Request().Context(), h.store, target, h.dqsKey)
	if err != nil {
		return h.badRequest(c, vm, err, "mail/blacklist")
	}

	vm["Result"] = rep
	return platform.Reply(c, http.StatusOK, rep, vm, "mail/blacklist", "mail/blacklist-result")
}

func (h *handler) dmarc(c *echo.Context) error {
	vm := h.vm("dmarc", "DMARC Report Visualizer & XML Analyzer", dmarcDesc)

	if c.Request().Method == http.MethodGet {
		return platform.Reply(c, http.StatusOK, nil, vm, "mail/dmarc", "mail/dmarc-result")
	}

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
			r = io.LimitReader(c.Request().Body, maxDMARCPayload)
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
	vm := h.vm("bimi", "BIMI SVG Tiny P/S & VMC Validator", bimiDesc)

	if c.Request().Method == http.MethodGet {
		return platform.Reply(c, http.StatusOK, nil, vm, "mail/bimi", "mail/bimi-result")
	}

	var svgData []byte
	file, err := c.FormFile("svg_file")
	if err == nil {
		f, err := file.Open()
		if err != nil {
			return h.badRequest(c, vm, err, "mail/bimi")
		}
		defer f.Close()
		svgData, err = io.ReadAll(io.LimitReader(f, maxBIMIPayload))
		if err != nil {
			return h.badRequest(c, vm, err, "mail/bimi")
		}
	} else {
		pasted := c.FormValue("svg")
		if strings.TrimSpace(pasted) == "" {
			return h.badRequest(c, vm, errors.New("please upload an SVG file or paste SVG markup"), "mail/bimi")
		}
		svgData = []byte(pasted)
	}

	res, err := ValidateBIMI(string(svgData))
	if err != nil {
		return h.badRequest(c, vm, err, "mail/bimi")
	}
	vm["Result"] = res
	return platform.Reply(c, http.StatusOK, res, vm, "mail/bimi", "mail/bimi-result")
}

func (h *handler) bimiFix(c *echo.Context) error {
	svg := c.FormValue("svg")
	if strings.TrimSpace(svg) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "no SVG provided"})
	}
	fixed, err := AutoFixBIMI(svg)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"svg": fixed, "fixed_svg": fixed})
}

func (h *handler) arc(c *echo.Context) error {
	vm := h.vm("arc", "ARC (Authenticated Received Chain) Header Analyzer", arcDesc)

	if c.Request().Method == http.MethodGet {
		return platform.Reply(c, http.StatusOK, nil, vm, "mail/arc", "mail/arc-result")
	}

	headers := strings.TrimSpace(c.FormValue("headers"))
	if headers == "" {
		return h.badRequest(c, vm, errors.New("please paste email headers containing ARC-Seal and ARC-Authentication-Results"), "mail/arc")
	}

	res, err := AnalyzeARC(headers)
	if err != nil {
		return h.badRequest(c, vm, err, "mail/arc")
	}
	vm["Result"] = res
	return platform.Reply(c, http.StatusOK, res, vm, "mail/arc", "mail/arc-result")
}

func (h *handler) arcParse(c *echo.Context) error {
	headers := strings.TrimSpace(c.FormValue("headers"))
	if headers == "" {
		body, _ := io.ReadAll(io.LimitReader(c.Request().Body, maxARCPayload))
		headers = string(body)
	}
	if strings.TrimSpace(headers) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "no email headers provided"})
	}
	res, err := AnalyzeARC(headers)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, res)
}

func (h *handler) badRequest(c *echo.Context, vm map[string]any, err error, tmpl string) error {
	vm["Error"] = err.Error()
	return platform.Reply(c, http.StatusBadRequest, map[string]string{"error": err.Error()}, vm, tmpl, "mail/error")
}

func limited(c *echo.Context) error {
	return c.String(http.StatusTooManyRequests, "Rate limit exceeded. Please wait a moment.")
}

// SitemapPages lists all public routes for sitemap.xml.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{
		{Path: "/"},
		{Path: "/disposable"},
		{Path: "/classifier"},
		{Path: "/blacklist"},
		{Path: "/dmarc"},
		{Path: "/bimi"},
		{Path: "/arc"},
	}, nil
}
