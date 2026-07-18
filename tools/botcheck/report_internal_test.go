package botcheck

import "testing"

// TestEveryRuleHasAnExplanation is the G55 coverage guard: it lives white-box
// because the rule list is unexported. It fails the moment a rule lands without
// a ruleExplanations entry — including the 14 rules being built in parallel on
// the sibling branch, whose entries are pre-seeded here and must survive the
// merge (the second loop pins those reserved IDs by name).
func TestEveryConsistencyRuleHasSubgroup(t *testing.T) {
	for _, r := range rules {
		if r.tier == TierConsistency && r.subgroup == "" {
			t.Errorf("consistency rule %q (%s) has no subgroup", r.id, r.label)
		}
	}
}

func TestEveryRuleHasAnExplanation(t *testing.T) {
	for _, r := range rules {
		if ruleExplanations[r.id] == "" {
			t.Errorf("rule %q (%s) has no explanation", r.id, r.label)
		}
	}
	for _, id := range []string{
		"iframe_webdriver", "iframe_proxy", "mobile_no_touch", "webdriver_sw",
		"cdp_sw_only", "navigator_proto_tamper", "chrome_runtime_tamper",
		"chrome_late_injection", "jsengine_ua_mismatch", "webrtc_ip_mismatch",
		"image_broken", "system_color_headless", "plugins_mimetypes_incoherent",
		"zero_outer_height",
	} {
		if ruleExplanations[id] == "" {
			t.Errorf("reserved rule ID %q lost its pre-seeded explanation", id)
		}
	}
}
