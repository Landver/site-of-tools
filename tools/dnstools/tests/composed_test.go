package tests

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

func TestLookupEnrichedAppliesTheDefaults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, qtype, resolver string
		want                  []any
	}{
		{"https://Example.COM/x", "", "", []any{"example.com", "cloudflare", []string(nil)}},
		{"example.com", " all ", "", []any{"example.com", "cloudflare", []string(nil)}},
		{"example.com", "mx", " GOOGLE ", []any{"example.com", "google", []string{"MX"}}},
	} {
		f := &fakeLooker{set: sampleSet()}
		if _, err := dnstools.LookupEnriched(context.Background(), f, nil, tc.name, tc.qtype, tc.resolver); err != nil {
			t.Fatalf("%q: %v", tc.name, err)
		}
		if diff := cmp.Diff(tc.want, []any{f.lastName, f.lastRes, f.lastTypes}); diff != "" {
			t.Errorf("%q %q %q asked (-want +got):\n%s", tc.name, tc.qtype, tc.resolver, diff)
		}
	}
}

func TestLookupEnrichedTagsAddressesOnly(t *testing.T) {
	t.Parallel()
	set, err := dnstools.LookupEnriched(context.Background(), &goldenDNS{}, testGeo(), "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range set.Found {
		got[r.Type] = r.Records[0].ASN
	}
	if diff := cmp.Diff(map[string]string{"A": "64500", "AAAA": "64500", "MX": ""}, got); diff != "" {
		t.Errorf("ASN per type (-want +got):\n%s", diff)
	}

	if _, err := dnstools.LookupEnriched(context.Background(), &goldenDNS{lookErr: dnstools.ErrBadType}, testGeo(), "example.com", "ANY", ""); !errors.Is(err, dnstools.ErrBadType) {
		t.Errorf("err = %v, want ErrBadType", err)
	}
}

func TestConsistencyComposesTheCheck(t *testing.T) {
	t.Parallel()
	dom, _ := goldenUpstream(t, http.StatusOK, http.StatusOK)
	svc := &goldenDNS{}
	env, err := dnstools.Consistency(context.Background(), svc, svc, testGeo(), dom, "https://Example.com/x", "")
	if err != nil {
		t.Fatal(err)
	}
	if env.Name != "example.com" || env.Type != "A" || env.ECS == nil || env.ECS.Type != "A" {
		t.Errorf("name %q type %q ecs %+v: want the normalised name, type A, and the card", env.Name, env.Type, env.ECS)
	}
	if len(env.Health) != 2 {
		t.Errorf("health = %+v, want the ASN and registry findings", env.Health)
	}

	env, err = dnstools.Consistency(context.Background(), svc, &goldenDNS{ecsErr: errors.New("no")}, nil, nil, "example.com", "aaaa")
	if err != nil || env.ECS != nil || env.Type != "AAAA" || len(env.Health) != 0 {
		t.Errorf("failed card: env %+v err %v, want no ECS, type AAAA, no health", env, err)
	}
	if _, err := dnstools.Consistency(context.Background(), nil, svc, nil, nil, "example.com", ""); !errors.Is(err, dnstools.ErrDisabled) {
		t.Errorf("no spreader: err = %v, want ErrDisabled", err)
	}
	if _, err := dnstools.Consistency(context.Background(), &goldenDNS{spreadErr: dnstools.ErrNeedDomain}, nil, nil, nil, "1.1.1.1", ""); !errors.Is(err, dnstools.ErrNeedDomain) {
		t.Errorf("err = %v, want the spread's own", err)
	}
}

func TestDomainInfoRefusesWhatIsNotADomain(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]error{"1.1.1.1": dnstools.ErrNeedDomain, "a..b": dnstools.ErrBadName, " ": dnstools.ErrEmptyName} {
		rep, err := dnstools.DomainInfo(context.Background(), &goldenDNS{}, nil, in)
		if !errors.Is(err, want) || rep != nil {
			t.Errorf("%q: report %v err %v, want %v", in, rep, err, want)
		}
	}
}

// Err is what both transports judge a report by: 503, 502 or an answer.
func TestDomainReportErr(t *testing.T) {
	t.Parallel()
	_, ctDownHost := goldenUpstream(t, http.StatusInternalServerError, http.StatusInternalServerError)
	rdapOffCTDown := dnstools.NewDomainClient("", "http://"+ctDownHost, 5*time.Second)
	bothDown, _ := goldenUpstream(t, http.StatusInternalServerError, http.StatusBadGateway)
	absentCTDown, _ := goldenUpstream(t, http.StatusNotFound, http.StatusInternalServerError)
	rdapDown, _ := goldenUpstream(t, http.StatusInternalServerError, http.StatusOK)

	for _, tc := range []struct {
		name      string
		svc       dnstools.Looker
		dom       *dnstools.DomainClient
		want      string
		delegated bool
	}{
		{name: "no client", svc: &goldenDNS{}, want: "disabled"},
		{name: "rdap off, ct down", svc: &goldenDNS{}, dom: rdapOffCTDown, want: "failed"},
		{name: "both down", svc: &goldenDNS{}, dom: bothDown, want: "failed"},
		{name: "absent, delegated", svc: &goldenDNS{delegated: true}, dom: absentCTDown, want: "ok", delegated: true},
		{name: "absent, undelegated", svc: &goldenDNS{}, dom: absentCTDown, want: "failed"},
		{name: "partial", svc: &goldenDNS{}, dom: rdapDown, want: "ok"},
	} {
		rep, err := dnstools.DomainInfo(context.Background(), tc.svc, tc.dom, "example.com")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := "ok"
		switch err := rep.Err(); {
		case errors.Is(err, dnstools.ErrDisabled):
			got = "disabled"
		case err != nil:
			got = "failed"
		}
		if got != tc.want || rep.Delegated != tc.delegated {
			t.Errorf("%s: Err() = %v (%s), delegated %v; want %s, delegated %v", tc.name, rep.Err(), got, rep.Delegated, tc.want, tc.delegated)
		}
	}
}

func TestEmailReportAddsReputationWhenWired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := &goldenDNS{}

	res, err := dnstools.EmailReport(ctx, svc, svc, &repCorpus{}, " Example.com ")
	if err != nil || res.Domain != "example.com" || res.MXRep == nil || res.MXRep.Domain != "example.com" {
		t.Fatalf("report %+v err %v, want the normalised domain with its reputation", res, err)
	}
	for name, rep := range map[string]dnstools.Reputer{"no reputer": nil, "reputation failed": &goldenDNS{repErr: dnstools.ErrNoBlocklist}} {
		if res, err := dnstools.EmailReport(ctx, svc, rep, &repCorpus{}, "example.com"); err != nil || res.MXRep != nil {
			t.Errorf("%s: MXRep %v err %v, want the report without the card", name, res.MXRep, err)
		}
	}
	if res, err := dnstools.EmailReport(ctx, svc, svc, nil, "example.com"); err != nil || res.MXRep != nil {
		t.Errorf("no corpus: MXRep %v err %v, want the report without the card", res.MXRep, err)
	}
	if _, err := dnstools.EmailReport(ctx, nil, svc, &repCorpus{}, "example.com"); !errors.Is(err, dnstools.ErrDisabled) {
		t.Errorf("no mailer: err = %v, want ErrDisabled", err)
	}
	if _, err := dnstools.EmailReport(ctx, &goldenDNS{mailErr: dnstools.ErrNeedDomain}, svc, &repCorpus{}, "1.1.1.1"); !errors.Is(err, dnstools.ErrNeedDomain) {
		t.Errorf("err = %v, want the check's own", err)
	}
}
