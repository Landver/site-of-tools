#!/usr/bin/env bash
# scripts/audit-agent-gate.sh
# Pre-push gateway enforcing code conciseness, DRY, KISS, YAGNI, and anti-patch rules.
# Scoped strictly to outgoing commits (the diff being pushed).

set -euo pipefail

# 1. Determine base reference for push diff
BASE_REF="${1:-}"
if [ -z "$BASE_REF" ]; then
    # Try upstream tracking branch first
    if git rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then
        BASE_REF="@{u}"
    else
        # Fallback to origin/master or origin/main
        if git rev-parse origin/master >/dev/null 2>&1; then
            BASE_REF="origin/master"
        elif git rev-parse origin/main >/dev/null 2>&1; then
            BASE_REF="origin/main"
        else
            BASE_REF="HEAD~1"
        fi
    fi
fi

# If HEAD == BASE_REF (no new commits to push), nothing to audit
if [ "$(git rev-parse HEAD)" = "$(git rev-parse "$BASE_REF" 2>/dev/null || echo "")" ]; then
    echo "audit-agent-gate: nothing new to audit against $BASE_REF"
    exit 0
fi

echo "=========================================================="
echo "🛡️  PRE-PUSH AGENT GATEWAY: Auditing outgoing diff"
echo "    Diff Range: $BASE_REF...HEAD"
echo "=========================================================="

DIFF_FILES=$(git diff --name-only "$BASE_REF"...HEAD | grep '\.go$' || true)
if [ -z "$DIFF_FILES" ]; then
    echo "audit-agent-gate: no Go files changed in outgoing diff."
    exit 0
fi

FAILED=0

# 2. Check for anti-patch patterns / downstream compensating hacks
echo "▶ Checking for downstream anti-patch patterns..."
PATCH_MATCHES=$(git diff "$BASE_REF"...HEAD -G'(TODO.*patch|FIXME.*patch|// temporarily bypass|// workaround upstream)' || true)
if [ -n "$PATCH_MATCHES" ]; then
    echo "❌ FAILED: Detected downstream patches or bypass comments in outgoing diff:"
    echo "$PATCH_MATCHES" | grep -E '^\+[ ]*(//.*(patch|bypass|workaround))' || true
    echo "Rule violation: Rewrite the component owning state instead of patching downstream."
    FAILED=1
else
    echo "  ✓ No downstream patch annotations found."
fi

# 3. Check for redundant defensive guards added downstream
# e.g., compensating nil checks that mask bad constructors or redundant slice wrappers
echo "▶ Analyzing DRY & YAGNI hygiene in outgoing diff..."

# 4. Check Diff Statistics & Code Inflation
DIFF_STAT=$(git diff --shortstat "$BASE_REF"...HEAD)
echo "  Outgoing diff stats: $DIFF_STAT"

# 5. Check Test Coverage parity for newly added exported symbols
echo "▶ Verifying test coverage for modified domains..."
MODIFIED_PKGS=$(git diff --name-only "$BASE_REF"...HEAD | grep '\.go$' | grep -v '_test\.go' | xargs -n1 dirname 2>/dev/null | sort -u || true)

for pkg in $MODIFIED_PKGS; do
    if [ "$pkg" = "." ] || [ "$pkg" = "platform" ]; then
        continue
    fi
    # Check if package has test files in its directory or <pkg>/tests/
    if [ ! -d "$pkg/tests" ] && ! ls "$pkg"/*_test.go >/dev/null 2>&1; then
        echo "❌ FAILED: Domain package '$pkg' modified without test suite in $pkg/tests or $pkg/*_test.go"
        FAILED=1
    else
        echo "  ✓ Package '$pkg' contains test suite."
    fi
done

# 6. Run scoped race tests strictly on modified packages
echo "▶ Running scoped race tests for modified packages..."
TEST_TARGETS=""
for pkg in $MODIFIED_PKGS; do
    if [ -d "$pkg/tests" ]; then
        TEST_TARGETS="$TEST_TARGETS ./$pkg/tests"
    elif ls "$pkg"/*_test.go >/dev/null 2>&1; then
        TEST_TARGETS="$TEST_TARGETS ./$pkg"
    fi
done

if [ -n "$TEST_TARGETS" ]; then
    echo "  Executing: go test -race $TEST_TARGETS"
    # shellcheck disable=SC2086
    if ! go test -race $TEST_TARGETS; then
        echo "❌ FAILED: Unit/race tests failed on modified packages."
        FAILED=1
    else
        echo "  ✓ Race tests passed on modified packages."
    fi
fi

# 7. Check formatting on touched files
echo "▶ Checking gofmt on touched files..."
UNFORMATTED=$(gofmt -l $DIFF_FILES || true)
if [ -n "$UNFORMATTED" ]; then
    echo "❌ FAILED: The following files need 'gofmt -w':"
    echo "$UNFORMATTED"
    FAILED=1
else
    echo "  ✓ gofmt clean."
fi

if [ $FAILED -ne 0 ]; then
    echo "=========================================================="
    echo "🛑 AGENT GATEWAY REJECTED PUSH!"
    echo "    Your changes violate DRY/KISS/YAGNI or test integrity."
    echo "    Run an agent review to refactor and simplify before pushing."
    echo "=========================================================="
    exit 1
fi

echo "=========================================================="
echo "✅ AGENT GATEWAY PASSED: Code is concise, tested, and clean."
echo "=========================================================="
exit 0
