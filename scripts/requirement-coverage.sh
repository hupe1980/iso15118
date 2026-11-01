#!/bin/sh
# Classifies every ISO 15118-2 requirement this repository cites by what stands
# behind the citation:
#
#   tested       cited in tests/ or inside a `#[cfg(test)]` module, and in src/
#   implemented  cited in src/ outside tests, and in no test
#   tested-only  cited in a test and nowhere in src/
#   cited-only   cited only in documentation (README, site, examples, CHANGELOG)
#
# The s2n-quic "duvet" idea at the size this crate needs. It sits on top of
# scripts/verify-citations.sh, which checks that each number names a requirement
# the standard defines; this one asks what the repository does about it.
#
# The bound, stated: a citation in a test shows that a test *names* the
# requirement, not that it covers every clause of it. Reading the test is still
# the review. Set ISO15118_COVERAGE_LIST=1 to print each requirement's class.
#
# Needs nothing but a POSIX shell, grep and awk, so it runs anywhere — CI
# included.
set -eu

BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"

pattern='V2G2-[0-9]+'

# Citations in src/, split at each file's first `#[cfg(test)]`: lines after it
# are test code.
src_cites() {
    want="$1"
    find src -name '*.rs' -not -path 'src/generated/*' | while read -r f; do
        awk -v want="$want" -v pat="$pattern" '
            /#\[cfg\(test\)\]/ { in_test = 1 }
            {
                line = $0
                while (match(line, pat)) {
                    id = substr(line, RSTART, RLENGTH)
                    if ((want == "test") == (in_test == 1)) print id
                    line = substr(line, RSTART + RLENGTH)
                }
            }' "$f"
    done
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

src_cites impl | sort -u > "$tmp/impl"
{ src_cites test; grep -rhoE "$pattern" tests 2>/dev/null || true; } | sort -u > "$tmp/test"
grep -rhoE "$pattern" README.md CHANGELOG.md site/content examples 2>/dev/null | sort -u > "$tmp/docs" || true
cat "$tmp/impl" "$tmp/test" "$tmp/docs" | sort -u > "$tmp/all"

tested=$(comm -12 "$tmp/impl" "$tmp/test")
implemented=$(comm -23 "$tmp/impl" "$tmp/test")
tested_only=$(comm -13 "$tmp/impl" "$tmp/test")
cited_only=$(sort -u "$tmp/impl" "$tmp/test" | comm -13 - "$tmp/docs")

count() { [ -z "$1" ] && echo 0 || printf '%s\n' "$1" | wc -l | tr -d ' '; }

if [ -n "${ISO15118_COVERAGE_LIST:-}" ]; then
    for class in tested implemented tested_only cited_only; do
        eval "ids=\$$class"
        [ -n "$ids" ] && printf '%s\n' "$ids" | sed "s/^/$class  /"
    done
fi

echo "$(count "$(cat "$tmp/all")") distinct [V2G2-nnn] cited:"
echo "  tested       $(count "$tested")   in src/ and in a test"
echo "  implemented  $(count "$implemented")   in src/, named by no test"
echo "  tested-only  $(count "$tested_only")   in a test, not in src/"
echo "  cited-only   $(count "$cited_only")   in documentation only"
