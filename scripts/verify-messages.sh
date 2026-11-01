#!/bin/sh
# Round-trips every message type through the generated codec, against bytes
# produced by the EXI reference implementation.
#
# For each global element of each schema set, `iso15118-codegen --samples`
# writes a schema-valid XML instance; exificient encodes it as an EXI document
# and again as an EXI fragment; the generated Rust decodes those bytes and
# re-encodes them. The result must be byte-identical both ways.
#
# The fragment half is what Plug & Charge signatures are computed over, and it
# uses a different root table from the document half — so it is a genuinely
# separate claim about the wire format, not a restatement of the first.
#
# Golden vectors cover a handful of messages. This covers all of them, including
# the fields no captured trace happens to populate.
#
# Requirements, none of which CI has: the fetched schemas, a JDK, and the
# exificient jars (downloaded on first run into the same place
# scripts/verify-grammars.sh uses).
set -eu

BASE="$(cd "$(dirname "$0")/.." && pwd)"
BASE_DIR_FOR_SCHEMAS="$BASE"
# shellcheck source=lib/schemas.sh
. "$BASE/scripts/lib/schemas.sh"
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

mkdir -p "$WORK/samples"
for jar in $JARS; do
    name=$(basename "$jar")
    [ -s "$WORK/$name" ] || { echo "fetching $name"; curl -sfSL -o "$WORK/$name" "$MAVEN/$jar"; }
done
CP="$(ls "$WORK"/*.jar | tr '\n' ':')$WORK"
javac -cp "$CP" -d "$WORK" "$BASE/tools/EncodeSamples.java" "$BASE/tools/EncodeFragments.java"

run() { cargo run --quiet --manifest-path "$BASE/Cargo.toml" -p iso15118-codegen -- "$@"; }

# module:schema pairs, matching scripts/generate.sh.
# module:schema:namespace. The namespace keeps imported xmldsig elements out of
# the samples: they are declarations the V2G schemas borrow, not V2G messages.
SETS="iso2:iso15118-2/V2G_CI_MsgDef.xsd:urn:iso:15118:2:2013:MsgDef,urn:iso:15118:2:2013:MsgBody
iso20_messages:iso15118-20/V2G_CI_CommonMessages.xsd:urn:iso:std:iso:15118:-20:CommonMessages
iso20_ac:iso15118-20/V2G_CI_AC.xsd:urn:iso:std:iso:15118:-20:AC
iso20_dc:iso15118-20/V2G_CI_DC.xsd:urn:iso:std:iso:15118:-20:DC
iso20_wpt:iso15118-20/V2G_CI_WPT.xsd:urn:iso:std:iso:15118:-20:WPT
iso20_acdp:iso15118-20/V2G_CI_ACDP.xsd:urn:iso:std:iso:15118:-20:ACDP
iso20_ac_der_iec:iso15118-20/V2G_CI_AC_DER_IEC.xsd:urn:iso:std:iso:15118:-20:AC,urn:iso:std:iso:15118:-20:AC-DER-IEC
iso20_ac_der_sae:iso15118-20/V2G_CI_AC_DER_SAE.xsd:urn:iso:std:iso:15118:-20:AC,urn:iso:std:iso:15118:-20:AC-DER-SAE"

# Agreeing with the reference proves nothing about a schema nobody pinned: both
# sides would read the same changed file. Refuse it before comparing.
# shellcheck disable=SC2046
verify_schemas $(pinned_schemas) || exit 1

for pair in $SETS; do
    module=${pair%%:*}
    rest=${pair#*:}
    schema="$SCHEMA_DIR/${rest%%:*}"
    namespace=${rest#*:}
    [ -f "$schema" ] || { echo "skip     $module (run scripts/fetch-schemas.sh)"; continue; }
    rm -rf "$WORK/samples/$module"
    nsargs=""
    for ns in $(echo "$namespace" | tr ',' ' '); do
        nsargs="$nsargs --emit-ns $ns"
    done
    # shellcheck disable=SC2086
    run "$schema" --samples $nsargs -o "$WORK/samples/$module" 2>/dev/null
    java -Xss64m -cp "$CP" EncodeSamples "$schema" "$WORK/samples/$module" \
        > "$WORK/samples/$module.vectors"
    # The same instances encoded as EXI *fragments* — the form ISO 15118 signs.
    java -Xss64m -cp "$CP" EncodeFragments "$schema" "$WORK/samples/$module" \
        > "$WORK/samples/$module.fragments"
done

out="$WORK/reference_messages.out"
status=0
ISO15118_VECTORS="$WORK/samples" cargo test --manifest-path "$BASE/Cargo.toml" \
    --all-features --test reference_messages -- --nocapture 2>&1 | tee "$out" || status=1
grep -q "test result: ok" "$out" || status=1

# The count the pages quote is the documents one; fragments are the same set.
if [ "$status" -eq 0 ]; then
    n=$(sed -n 's/^all \([0-9]*\) documents round-trip against the reference$/\1/p' "$out")
    . "$BASE/scripts/lib/claims.sh"
    claims_agree "$BASE" "all $n documents round-trip" || status=1
    claims_say "$BASE" README.md "All $n message types" || status=1
    claims_say "$BASE" site/content/docs/verification.md "$n messages differed" || status=1
    claims_say "$BASE" site/config.toml "messages = \"$n\"" || status=1
fi
exit "$status"
