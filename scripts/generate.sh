#!/bin/sh
# Regenerates src/generated/ from the XSD schemas in specs/.
#
# Run scripts/fetch-schemas.sh first. The generated files are committed, so this
# only needs running when the codegen or the schemas change; `git diff` after it
# is the review.
set -eu

BASE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$BASE/src/generated"
SPECS="$BASE/specs"
CT=urn:iso:std:iso:15118:-20:CommonTypes
# A few xmldsig types are ordinary structs that the V2G schemas reference
# directly (X509IssuerSerial, for one). They go alongside CommonTypes.
DS=http://www.w3.org/2000/09/xmldsig#

run() { cargo run --quiet --manifest-path "$BASE/Cargo.toml" -p iso15118-codegen -- "$@"; }

if [ ! -d "$SPECS/iso15118-2" ]; then
    echo "error: no schemas; run scripts/fetch-schemas.sh first" >&2
    exit 1
fi

mkdir -p "$OUT/iso20"

echo "ISO 15118-2"
run "$SPECS/iso15118-2/V2G_CI_MsgDef.xsd" --emit -o "$OUT/iso2.rs"

echo "ISO 15118-20"
# CommonTypes is shared by every -20 schema, so it is generated once and the
# others refer to it rather than duplicating a hundred types five times.
run "$SPECS/iso15118-20/V2G_CI_CommonTypes.xsd" --emit --emit-ns "$CT" --emit-ns "$DS" \
    -o "$OUT/iso20/common.rs"
for pair in CommonMessages:messages AC:ac DC:dc WPT:wpt ACDP:acdp; do
    schema=${pair%%:*}
    module=${pair##*:}
    ns="urn:iso:std:iso:15118:-20:$schema"
    run "$SPECS/iso15118-20/V2G_CI_$schema.xsd" --emit \
        --emit-ns "$ns" --extern "$CT=super::common" --extern "$DS=super::common" \
        -o "$OUT/iso20/$module.rs"
done

cargo fmt --manifest-path "$BASE/Cargo.toml" --all
echo "done."
