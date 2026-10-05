package mcptools

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// White-box: no owner tool reports the headers it was handed, so a probe tool
// on the owner server shows what a handler gets.

type probe struct {
	header http.Header
	who    caller
}

func TestOwnerHandlerSeesNoKeyButTheCaller(t *testing.T) {
	client, err := mongo.Connect(options.Client().ApplyURI("mongodb://127.0.0.1:1/").
		SetServerSelectionTimeout(200 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	owner := linktools.NewShortener(linktools.NewLinkStore(context.Background(), client.Database("offline")), "k3y", "http://link.test")
	h, err := newHandler(Deps{Owner: owner}, "http://mcp.test", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan probe, 1)
	mcp.AddTool(h.endpoints[ownerEndpoint].server, &mcp.Tool{Name: "probe"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			seen <- probe{header: req.Extra.Header.Clone(), who: *callerFrom(ctx)}
			return nil, map[string]any{}, nil
		})
	e := echo.New()
	h.routes(e)
	srv := httptest.NewServer(e)
	defer srv.Close()

	for _, auth := range []map[string]string{{"X-Api-Key": "k3y"}, {"Authorization": "Bearer k3y"}} {
		hdr := map[string]string{"User-Agent": "probe-agent"}
		for k, v := range auth {
			hdr[k] = v
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "1"}, nil).Connect(context.Background(),
			&mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp/owner", HTTPClient: &http.Client{Transport: headers(hdr)}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "probe"}); err != nil {
			t.Fatal(err)
		}
		cs.Close()
		got := <-seen
		if got.header.Get("X-Api-Key") != "" || got.header.Get("Authorization") != "" {
			t.Errorf("%v: the handler saw the key: %v", auth, got.header)
		}
		if w := got.who; w.ip != "127.0.0.1" || w.key != "127.0.0.1" || !w.owner || w.userAgent != "probe-agent" || w.http == nil ||
			!strings.HasPrefix(w.host, "127.0.0.1:") {
			t.Errorf("%v: caller in the handler = %+v, want the raw address, its key, the owner flag", auth, w)
		}
	}
}

type headers map[string]string

func (h headers) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}
