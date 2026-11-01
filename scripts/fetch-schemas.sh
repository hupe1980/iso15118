#!/bin/sh
# Fetch the ISO 15118 XSD schemas from ISO's official publication server into
# concepts/reference/ (gitignored, with the rest of the internal notes), or into
# $ISO15118_SCHEMAS_DIR.
#
# The XSDs are published by ISO as freely accessible electronic attachments to the
# standards; by downloading them you accept ISO's terms of use for these files.
# The full specification texts and the DIN/TS 70121 schemas are NOT freely
# available and must be obtained separately (iso.org, DIN Media).
#
# Every file is checked against its SHA-256 in scripts/schemas.sha256 before it
# is kept, and a file already on disk is checked too. A mismatch stops the
# script: the same URL serving different bytes is a different schema, and
# codegen must not read it until somebody has looked (see scripts/lib/schemas.sh).
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASE_DIR_FOR_SCHEMAS="$BASE_DIR"
# shellcheck source=lib/schemas.sh
. "$BASE_DIR/scripts/lib/schemas.sh"
DIR=$(schemas_dir)

ISO2_URL="https://standards.iso.org/iso/15118/-2/ed-2/en"
ISO20_URL="https://standards.iso.org/iso/15118/-20/ed-1/en"
# ISO 15118-20:2022/Amd 1:2026. The AC_DER schemas import V2G_CI_AC.xsd by
# relative path, so they live beside the -20 schemas rather than in a folder of
# their own.
AMD1_URL="https://standards.iso.org/iso/15118/-20/ed-1/en/Amd/1"

ISO2_FILES="V2G_CI_AppProtocol.xsd V2G_CI_MsgDef.xsd V2G_CI_MsgBody.xsd V2G_CI_MsgDataTypes.xsd V2G_CI_MsgHeader.xsd xmldsig-core-schema.xsd"
ISO20_FILES="V2G_CI_AC.xsd V2G_CI_ACDP.xsd V2G_CI_AppProtocol.xsd V2G_CI_CommonMessages.xsd V2G_CI_CommonTypes.xsd V2G_CI_DC.xsd V2G_CI_WPT.xsd xmldsig-core-schema.xsd"
AMD1_FILES="V2G_CI_AC_DER_IEC.xsd V2G_CI_AC_DER_SAE.xsd"

status=0
fetch() {
    url="$1" set="$2" files="$3"
    mkdir -p "$DIR/$set"
    for f in $files; do
        rel="$set/$f"
        if [ -s "$DIR/$rel" ]; then
            echo "exists   $rel"
        else
            echo "fetching $rel"
            curl -sfSL -o "$DIR/$rel.part" "$url/$f"
            mv "$DIR/$rel.part" "$DIR/$rel"
        fi
        verify_schemas "$rel" || status=1
    done
}

fetch "$ISO2_URL"  iso15118-2  "$ISO2_FILES"
fetch "$ISO20_URL" iso15118-20 "$ISO20_FILES"
fetch "$AMD1_URL"  iso15118-20 "$AMD1_FILES"

if [ "$status" -ne 0 ]; then
    echo "error: a schema does not match scripts/schemas.sha256 — see above" >&2
    exit 1
fi
echo "done: <schemas> = $DIR (every file matches its pin)"
