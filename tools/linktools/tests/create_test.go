package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// Every refusal but the last is decided before the store is touched; the last
// reaches the offline store's insert.
func TestCreateFromAnswersWithPublicErrors(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, tc := range []struct {
		name   string
		req    linktools.CreateRequest
		status int
		msg    string
	}{
		{"bad ttl", linktools.CreateRequest{URL: "https://example.com/", TTL: "soon"}, http.StatusBadRequest, "ttl is not a duration, e.g. 720h"},
		{"short ttl", linktools.CreateRequest{URL: "https://example.com/", TTL: "59s"}, http.StatusBadRequest, "ttl must be at least 1m; leave it out for a link that never expires"},
		{"bad target", linktools.CreateRequest{URL: "ftp://example.com/"}, http.StatusBadRequest, `destination URL not allowed: scheme "ftp" is not http or https`},
		{"clean without a cleaner", linktools.CreateRequest{URL: "https://example.com/", Clean: true}, http.StatusServiceUnavailable, "feature is not enabled: cleaning was requested but no cleaner is wired"},
		{"storage down", linktools.CreateRequest{URL: "https://example.com/", TTL: "720h"}, http.StatusInternalServerError, "Something went wrong on our side. Nothing was changed."},
	} {
		created, err := s.CreateFrom(context.Background(), tc.req, "192.0.2.1")
		if created != nil || err == nil {
			t.Fatalf("%s: created %+v err %v, want a refusal", tc.name, created, err)
		}
		if status, msg := linktools.PublicError(err); status != tc.status || msg != tc.msg {
			t.Errorf("%s: PublicError = %d %q, want %d %q", tc.name, status, msg, tc.status, tc.msg)
		}
	}
}

func TestPublicErrorNeverEchoesAStorageError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err    error
		status int
	}{
		{fmt.Errorf("%w: q4-report", linktools.ErrSlugTaken), http.StatusConflict},
		{linktools.ErrDisabled, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: bad", linktools.ErrInvalidSlug), http.StatusBadRequest},
		{fmt.Errorf("%w: long", linktools.ErrInvalidNote), http.StatusBadRequest},
		{errors.New("mongodb://admin:pw@10.0.0.5:27017: connection refused"), http.StatusInternalServerError},
	} {
		status, msg := linktools.PublicError(tc.err)
		switch {
		case status != tc.status:
			t.Errorf("%v: status %d, want %d", tc.err, status, tc.status)
		case status == http.StatusInternalServerError && strings.Contains(msg, "mongo"):
			t.Errorf("a storage error reached the caller: %q", msg)
		case status != http.StatusInternalServerError && msg != tc.err.Error():
			t.Errorf("%v: msg %q, want the error's own", tc.err, msg)
		}
	}
}

func TestCreatedKeepsTheAPIShape(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	exp := at.Add(720 * time.Hour)
	for _, tc := range []struct {
		name string
		in   linktools.Created
		want string
	}{
		{"permanent", linktools.Created{Code: "q4", CreatedAt: at, Short: "https://link.example/s/q4", Target: "https://example.com/", Note: "page only"},
			`{"code":"q4","created_at":"2026-10-04T12:00:00Z","expires_at":null,"hits":0,"short":"https://link.example/s/q4","target":"https://example.com/"}`},
		{"cleaned", linktools.Created{Cleaned: []string{"utm_source"}, Code: "q4", CreatedAt: at, ExpiresAt: &exp, Hits: 2,
			Original: "https://example.com/?utm_source=x", Short: "https://link.example/s/q4", Target: "https://example.com/"},
			`{"cleaned":["utm_source"],"code":"q4","created_at":"2026-10-04T12:00:00Z","expires_at":"2026-11-03T12:00:00Z","hits":2,"original":"https://example.com/?utm_source=x","short":"https://link.example/s/q4","target":"https://example.com/"}`},
	} {
		got, err := json.Marshal(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		var w, g any
		if json.Unmarshal([]byte(tc.want), &w) != nil || json.Unmarshal(got, &g) != nil {
			t.Fatalf("%s: not JSON: %s", tc.name, got)
		}
		if diff := cmp.Diff(w, g); diff != "" {
			t.Errorf("%s (-want +got):\n%s", tc.name, diff)
		}
	}
}

func TestCodeFromShortURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, base, code string
		ok             bool
	}{
		{"aB3xY9k", "https://link.example", "aB3xY9k", true},
		{" q4-report ", "https://link.example", "q4-report", true},
		{"https://link.example/s/aB3xY9k", "https://link.example", "aB3xY9k", true},
		{"HTTPS://LINK.EXAMPLE/s/q4-report?utm_source=x", "https://link.example/", "q4-report", true},
		{"link.example/s/q4-report", "https://link.example", "q4-report", true},
		{"/s/q4-report", "", "q4-report", true},
		{"https://evil.example/s/q4-report", "https://link.example", "", false},
		{"https://link.example/s/q4-report", "", "", false},
		{"https://link.example/q4-report", "https://link.example", "", false},
		{"https://link.example/s/a/b", "https://link.example", "", false},
		{"https://link.example/s/", "https://link.example", "", false},
		{"", "https://link.example", "", false},
	} {
		if code, ok := linktools.CodeFromShortURL(tc.in, tc.base); code != tc.code || ok != tc.ok {
			t.Errorf("CodeFromShortURL(%q, %q) = %q, %v; want %q, %v", tc.in, tc.base, code, ok, tc.code, tc.ok)
		}
	}
}

func TestCreateFromLive(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)
	created, err := s.CreateFrom(ctx, linktools.CreateRequest{URL: "https://example.com/a", TTL: "1h", Note: "n"}, "192.0.2.1")
	if err != nil {
		t.Fatalf("CreateFrom: %v", err)
	}
	if created.Short != s.ShortURL(created.Code) || created.ExpiresAt == nil || created.Note != "n" || created.Target != "https://example.com/a" {
		t.Errorf("created = %+v", created)
	}
}
