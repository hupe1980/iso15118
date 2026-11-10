#!/bin/sh
# Check every `[V2G2-nnn]` and `[V2G20-nnnn]` this repository cites against the
# text of ISO 15118-2:2014(E) and ISO 15118-20:2022(E) (with Amendment 1:2026)
# themselves.
#
# The crate's evidence standard says a protocol claim carries a golden vector, a
# differential run, or "a `[V2G2-nnn]` citation somebody actually read". The
# first two are machine-checked by their own scripts; the third was not, and it
# is the class of claim that reads perfectly while being wrong — a requirement
# number one digit out cites a real requirement about something else, and no
# test of the code can tell.
#
# This checks the half a machine can: that every requirement number cited here
# *exists*. Whether it says what the comment beside it says is still a person's
# job — but a citation that names nothing at all never gets that far, and four
# of those were found here by hand.
#
# ISO 15118-2:2014(E) and ISO 15118-20:2022(E) are paid documents that are
# nonetheless readable in full from a US Federal Highway Administration
# rulemaking docket, published there with ANSI's permission for the NEVI
# programme. Amendment 1:2026 to -20 is not on the docket; the free preview of
# it carries its requirements, and a `[V2G20-nnnn]` passes if either the 2022
# text or that preview defines it. The documents are fetched to a scratch
# directory and **never** written into the repository: the copyright notice on
# every page is explicit that copying is not permitted.
#
# Requirements, none of which CI has, which is why this is a script and not a
# test:
#   * network access to downloads.regulations.gov and cdn.standards.iteh.ai
#   * pdftotext (poppler)
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${ISO15118_VERIFY_DIR:-${TMPDIR:-/tmp}/iso15118-citation-verify}"
DOCKET="https://downloads.regulations.gov/FHWA-2022-0008-0405"
AMD1="https://cdn.standards.iteh.ai/samples/iso/iso-15118-20-2022-amd-1-2026/75d10c61b25f4af1b583de9bf740facd/iso-15118-20-2022-amd-1-2026.pdf"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

command -v pdftotext >/dev/null 2>&1 || {
    echo "pdftotext not found — install poppler (brew install poppler)" >&2
    exit 1
}

# fetch NAME TITLE URL: download once into $WORK/NAME.pdf, extract NAME.txt.
fetch() {
    [ -s "$WORK/$1.txt" ] && return 0
    echo "fetching $2..."
    # The CDN in front of the docket refuses a bare curl; it wants a browser
    # user agent and the referer the download link would have carried.
    curl -sS -A "$UA" -H "Referer: https://www.regulations.gov/" \
        -o "$WORK/$1.pdf" "$3"
    case "$(file -b "$WORK/$1.pdf")" in
        PDF*) ;;
        *) echo "$3 did not return a PDF — fetch it by hand into $WORK/$1.pdf" >&2
           rm -f "$WORK/$1.pdf"; exit 1 ;;
    esac
    pdftotext -layout "$WORK/$1.pdf" "$WORK/$1.txt"
}

mkdir -p "$WORK"
fetch iso15118-2 "ISO 15118-2:2014(E) from the FHWA docket" "$DOCKET/attachment_2.pdf"
fetch iso15118-20 "ISO 15118-20:2022(E) from the FHWA docket" "$DOCKET/attachment_3.pdf"
fetch iso15118-20-amd1 "the ISO 15118-20:2022/Amd 1:2026 preview" "$AMD1"

# check PREFIX TITLE TEXT...: every PREFIX-nnn the repository cites against
# every [PREFIX-nnn] the TEXTs define; a citation none defines fails by name.
status=0
check() {
    prefix="$1"; title="$2"; shift 2
    grep -rhoE "$prefix-[0-9]+" \
        "$BASE_DIR/src" "$BASE_DIR/tests" "$BASE_DIR/examples" "$BASE_DIR/codegen/src" \
        "$BASE_DIR/site/content" "$BASE_DIR/README.md" \
        ${ISO15118_CONCEPTS:+"$BASE_DIR/concepts"} 2>/dev/null \
        | sort -u > "$WORK/cited-$prefix.txt"
    cat "$@" | grep -ohE "\[$prefix-[0-9]+\]" | tr -d '[]' | sort -u \
        > "$WORK/defined-$prefix.txt"

    missing="$(comm -23 "$WORK/cited-$prefix.txt" "$WORK/defined-$prefix.txt")"
    cited=$(wc -l < "$WORK/cited-$prefix.txt" | tr -d ' ')
    defined=$(wc -l < "$WORK/defined-$prefix.txt" | tr -d ' ')

    if [ -n "$missing" ]; then
        echo "citations that name no requirement in $title:"
        echo "$missing" | sed 's/^/  /'
        status=1
    else
        echo "ok: all $cited cited $prefix requirements exist among $title's $defined"
    fi
}

# `V2G2-ED2-nnnn` never matches `V2G2-[0-9]+` — a digit must follow `V2G2-` —
# and that is the right outcome rather than an exclusion anyone wrote: those
# numbers belong to the second edition, which is not this document and is not
# freely readable, so this script could not check them. `V2G20-nnnn` does not
# match it either, for the same reason.
check V2G2 "ISO 15118-2:2014" "$WORK/iso15118-2.txt"
check V2G20 "ISO 15118-20:2022 with Amd 1:2026" \
    "$WORK/iso15118-20.txt" "$WORK/iso15118-20-amd1.txt"
exit "$status"
