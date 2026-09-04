#!/bin/sh
# Check every `[V2G2-nnn]` this repository cites against the text of
# ISO 15118-2:2014(E) itself.
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
# ISO 15118-2:2014(E) is a paid document that is nonetheless readable in full
# from a US Federal Highway Administration rulemaking docket, published there
# with ANSI's permission for the NEVI programme. It is fetched to a scratch
# directory and **never** written into the repository: the copyright notice on
# every page is explicit that copying is not permitted.
#
# Requirements, none of which CI has, which is why this is a script and not a
# test:
#   * network access to downloads.regulations.gov
#   * pdftotext (poppler)
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${ISO15118_VERIFY_DIR:-${TMPDIR:-/tmp}/iso15118-citation-verify}"
DOCKET="https://downloads.regulations.gov/FHWA-2022-0008-0405/attachment_2.pdf"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

command -v pdftotext >/dev/null 2>&1 || {
    echo "pdftotext not found — install poppler (brew install poppler)" >&2
    exit 1
}

mkdir -p "$WORK"
if [ ! -s "$WORK/iso15118-2.txt" ]; then
    echo "fetching ISO 15118-2:2014(E) from the FHWA docket..."
    # The CDN in front of the docket refuses a bare curl; it wants a browser
    # user agent and the referer the download link would have carried.
    curl -sS -A "$UA" -H "Referer: https://www.regulations.gov/" \
        -o "$WORK/iso15118-2.pdf" "$DOCKET"
    case "$(file -b "$WORK/iso15118-2.pdf")" in
        PDF*) ;;
        *) echo "the docket did not return a PDF — fetch it by hand into $WORK/iso15118-2.pdf" >&2
           rm -f "$WORK/iso15118-2.pdf"; exit 1 ;;
    esac
    pdftotext -layout "$WORK/iso15118-2.pdf" "$WORK/iso15118-2.txt"
fi

# Every requirement number the repository cites, and every one the standard
# defines. `V2G2-ED2-nnnn` is deliberately excluded: those belong to the second
# edition, which is not this document and is not freely readable — see
# RISKS.md.
grep -rhoE 'V2G2-[0-9]+' \
    "$BASE_DIR/src" "$BASE_DIR/tests" "$BASE_DIR/examples" "$BASE_DIR/codegen/src" \
    "$BASE_DIR/site/content" "$BASE_DIR/README.md" \
    ${ISO15118_CONCEPTS:+"$BASE_DIR/concepts"} 2>/dev/null \
    | sort -u > "$WORK/cited.txt"
grep -ohE '\[V2G2-[0-9]+\]' "$WORK/iso15118-2.txt" | tr -d '[]' | sort -u > "$WORK/defined.txt"

missing="$(comm -23 "$WORK/cited.txt" "$WORK/defined.txt")"
cited=$(wc -l < "$WORK/cited.txt" | tr -d ' ')
defined=$(wc -l < "$WORK/defined.txt" | tr -d ' ')

if [ -n "$missing" ]; then
    echo "citations that name no requirement in ISO 15118-2:2014:"
    echo "$missing" | sed 's/^/  /'
    exit 1
fi
echo "ok: all $cited cited requirements exist among the standard's $defined"
