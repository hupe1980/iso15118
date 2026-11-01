#!/bin/sh
# Differentially verify this crate's EXI grammar derivation against the EXI
# reference implementation, for every V2G schema.
#
# `iso15118-codegen --dump` and `tools/GrammarDump.java` emit the same canonical
# flat-graph format; `tools/compare_grammars.py` walks both in lockstep and
# reports any state or production that differs.
#
# This is the strongest correctness evidence the project has: it checks the
# whole grammar of every message type, not just the paths a golden vector
# happens to take.
#
# Requirements, none of which CI has, which is why this is a script and not a
# test:
#   * the XSD schemas — run scripts/fetch-schemas.sh first
#   * a JDK
#   * the exificient jars (downloaded here on first run)
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASE_DIR_FOR_SCHEMAS="$BASE_DIR"
# shellcheck source=lib/schemas.sh
. "$BASE_DIR/scripts/lib/schemas.sh"
SCHEMA_DIR=$(schemas_dir)
WORK="${ISO15118_VERIFY_DIR:-${TMPDIR:-/tmp}/iso15118-grammar-verify}"
MAVEN=https://repo1.maven.org/maven2
JARS="com/siemens/ct/exi/exificient-core/1.0.7/exificient-core-1.0.7.jar
com/siemens/ct/exi/exificient-grammars/1.0.7/exificient-grammars-1.0.7.jar
com/siemens/ct/exi/exificient/1.0.7/exificient-1.0.7.jar
xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar
xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar
org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar
org/slf4j/slf4j-nop/1.7.36/slf4j-nop-1.7.36.jar"

# macOS ships a `java` stub that only prints an installation notice, so prefer
# an explicit JAVA_HOME and fall back to Homebrew's JDK before giving up.
if [ -z "${JAVA_HOME:-}" ]; then
    for candidate in /opt/homebrew/opt/openjdk /usr/local/opt/openjdk; do
        [ -x "$candidate/bin/javac" ] && JAVA_HOME="$candidate" && break
    done
fi
[ -n "${JAVA_HOME:-}" ] && PATH="$JAVA_HOME/bin:$PATH" && export PATH
if ! javac -version >/dev/null 2>&1; then
    echo "error: a JDK is required; set JAVA_HOME to one" >&2
    exit 1
fi

mkdir -p "$WORK"
for jar in $JARS; do
    name=$(basename "$jar")
    [ -s "$WORK/$name" ] || { echo "fetching $name"; curl -sfSL -o "$WORK/$name" "$MAVEN/$jar"; }
done

CP="$(ls "$WORK"/*.jar | tr '\n' ':')$WORK"
javac -cp "$CP" -d "$WORK" "$BASE_DIR/tools/GrammarDump.java"

SCHEMAS="iso15118-2/V2G_CI_AppProtocol.xsd
iso15118-2/V2G_CI_MsgDef.xsd
iso15118-20/V2G_CI_CommonMessages.xsd
iso15118-20/V2G_CI_AC.xsd
iso15118-20/V2G_CI_DC.xsd
iso15118-20/V2G_CI_WPT.xsd
iso15118-20/V2G_CI_ACDP.xsd
iso15118-20/V2G_CI_AC_DER_IEC.xsd
iso15118-20/V2G_CI_AC_DER_SAE.xsd"

# Agreeing with the reference proves nothing about a schema nobody pinned: both
# sides would read the same changed file. Refuse it before comparing.
# shellcheck disable=SC2046
verify_schemas $(pinned_schemas) || exit 1

status=0
total=0
complete=1
for schema in $SCHEMAS; do
    path="$SCHEMA_DIR/$schema"
    if [ ! -f "$path" ]; then
        echo "skip     $schema (run scripts/fetch-schemas.sh)"
        complete=0
        continue
    fi
    printf '%-34s ' "$(basename "$schema")"
    java -Xss64m -cp "$CP" GrammarDump "$path" > "$WORK/reference.txt"
    cargo run --quiet --manifest-path "$BASE_DIR/Cargo.toml" -p iso15118-codegen -- \
        "$path" --dump 2>/dev/null > "$WORK/ours.txt"
    result=$(python3 "$BASE_DIR/tools/compare_grammars.py" "$WORK/reference.txt" "$WORK/ours.txt") \
        || status=1
    echo "$result"
    n=$(echo "$result" | sed -n 's/^all \([0-9]*\) element grammars agree.*/\1/p')
    total=$((total + ${n:-0}))
done

# Only a complete, clean run measures the number the pages quote.
if [ "$status" -eq 0 ] && [ "$complete" -eq 1 ]; then
    . "$BASE_DIR/scripts/lib/claims.sh"
    claims_agree "$BASE_DIR" "($total total)" || status=1
    v=site/content/docs/verification.md
    claims_say "$BASE_DIR" "$v" "all **$total** element grammars" || status=1
    claims_say "$BASE_DIR" "$v" "$total grammars" || status=1
    claims_say "$BASE_DIR" site/config.toml "grammars = \"$total\"" || status=1
fi

exit "$status"
