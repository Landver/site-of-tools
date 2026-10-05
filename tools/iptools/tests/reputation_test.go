package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/iptools"
)

type recordingChecker struct {
	lk    iptools.BlockLookup
	err   error
	asked []string
}

func (r *recordingChecker) Check(_ context.Context, ip string) (iptools.BlockLookup, error) {
	r.asked = append(r.asked, ip)
	return r.lk, r.err
}

func TestLookupWithReputation(t *testing.T) {
	listed := iptools.BlockLookup{Sources: []string{"ipsum", "rate-limiter"}, MaxCount: 4}
	cases := []struct {
		name      string
		svc       iptools.Looker
		chk       *recordingChecker // nil → no checker at all
		want      *iptools.Result
		wantErr   error
		wantAsked []string
	}{
		{"listed", copyLooker{}, &recordingChecker{lk: listed}, &iptools.Result{IP: "8.8.8.8", Blocklist: &listed}, nil, []string{"8.8.8.8"}},
		{"checked clean", copyLooker{}, &recordingChecker{}, &iptools.Result{IP: "8.8.8.8", Blocklist: &iptools.BlockLookup{}}, nil, []string{"8.8.8.8"}},
		{"no checker", copyLooker{}, nil, &iptools.Result{IP: "8.8.8.8"}, nil, nil},
		{"read failed means not checked", copyLooker{}, &recordingChecker{err: errors.New("mongo down")}, &iptools.Result{IP: "8.8.8.8"}, nil, []string{"8.8.8.8"}},
		{"failed lookup skips the checker", copyLooker{err: iptools.ErrUnavailable}, &recordingChecker{lk: listed}, nil, iptools.ErrUnavailable, nil},
		{"nil looker", nil, &recordingChecker{lk: listed}, nil, iptools.ErrUnavailable, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var chk iptools.Checker
			if tc.chk != nil {
				chk = tc.chk
			}
			got, err := iptools.LookupWithReputation(context.Background(), tc.svc, chk, "8.8.8.8")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("result (-want +got):\n%s", diff)
			}
			if tc.chk != nil {
				if diff := cmp.Diff(tc.wantAsked, tc.chk.asked); diff != "" {
					t.Errorf("checker asked (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// A nil *BlockList answers "not listed"; wrapped raw it would mark every
// lookup checked-clean.
func TestCheckerFromNilIsNoChecker(t *testing.T) {
	if chk := iptools.CheckerFrom(nil); chk != nil {
		t.Fatalf("CheckerFrom(nil) = %#v, want a nil interface", chk)
	}
	if iptools.CheckerFrom(&iptools.BlockList{}) == nil {
		t.Error("CheckerFrom(non-nil) = nil")
	}
	got, err := iptools.LookupWithReputation(context.Background(), copyLooker{}, iptools.CheckerFrom(nil), "8.8.8.8")
	if err != nil || got.Blocklist != nil {
		t.Errorf("lookup with CheckerFrom(nil) = %+v, %v; want no blocklist", got, err)
	}
}

func TestRoutable(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8":              true,
		"203.0.113.7":          true,
		"2001:4860:4860::8888": true,
		"127.0.0.1":            false,
		"::1":                  false,
		"10.0.0.1":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"fd00::1":              false,
		"169.254.1.1":          false,
		"fe80::1":              false,
		"0.0.0.0":              false,
		"::":                   false,
		"not-an-ip":            false,
		"":                     false,
	} {
		if got := iptools.Routable(ip); got != want {
			t.Errorf("Routable(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestOfflineNilService(t *testing.T) {
	var s *iptools.Service
	if s.Offline() != nil {
		t.Error("nil Service.Offline() != nil")
	}
}
