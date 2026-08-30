#!/bin/sh
# Fetch the ISO 15118 XSD schemas from ISO's official publication server into specs/.
#
# The XSDs are published by ISO as freely accessible electronic attachments to the
# standards; by downloading them you accept ISO's terms of use for these files.
# The full specification texts and the DIN SPEC 70121 schemas are NOT freely
# available and must be obtained separately — see specs/README.md.
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISO2_URL="https://standards.iso.org/iso/15118/-2/ed-2/en"
ISO20_URL="https://standards.iso.org/iso/15118/-20/ed-1/en"

ISO2_FILES="V2G_CI_AppProtocol.xsd V2G_CI_MsgDef.xsd V2G_CI_MsgBody.xsd V2G_CI_MsgDataTypes.xsd V2G_CI_MsgHeader.xsd xmldsig-core-schema.xsd"
ISO20_FILES="V2G_CI_AC.xsd V2G_CI_ACDP.xsd V2G_CI_AppProtocol.xsd V2G_CI_CommonMessages.xsd V2G_CI_CommonTypes.xsd V2G_CI_DC.xsd V2G_CI_WPT.xsd xmldsig-core-schema.xsd"

fetch() {
    url="$1" dir="$2" files="$3"
    mkdir -p "$dir"
    for f in $files; do
        if [ -s "$dir/$f" ]; then
            echo "exists   $dir/$f"
        else
            echo "fetching $dir/$f"
            curl -sfSL -o "$dir/$f" "$url/$f"
        fi
    done
}

fetch "$ISO2_URL"  "$BASE_DIR/specs/iso15118-2"  "$ISO2_FILES"
fetch "$ISO20_URL" "$BASE_DIR/specs/iso15118-20" "$ISO20_FILES"

echo "done."
