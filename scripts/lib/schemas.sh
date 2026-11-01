# Sourced by the scripts that read the ISO schemas. Pins them by content.
#
# `scripts/schemas.sha256` lists every schema file with its SHA-256, in the
# format `sha256sum -c` reads. ISO serves the -2 schemas from a folder named
# `ed-2` that still holds the 2014 text; when the second edition publishes that
# folder may change in place, and an unpinned fetch would then regenerate a
# different codec from the same command. A changed pin is a reviewed commit.

# The reference directory: `ISO15118_SCHEMAS_DIR`, or the default.
schemas_dir() {
    printf '%s\n' "${ISO15118_SCHEMAS_DIR:-$BASE_DIR_FOR_SCHEMAS/concepts/reference}"
}

_schemas_digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# verify_schemas REL... — each argument a path relative to the reference
# directory, as the manifest names it. A missing file is left to the caller's
# skip-by-name; a file the manifest does not list, or whose digest differs, is
# refused and the function returns 1 after reporting every mismatch.
verify_schemas() {
    _dir=$(schemas_dir)
    _manifest="$BASE_DIR_FOR_SCHEMAS/scripts/schemas.sha256"
    _bad=0
    for _rel in "$@"; do
        [ -f "$_dir/$_rel" ] || continue
        _want=$(awk -v p="$_rel" '$2 == p { print $1 }' "$_manifest")
        if [ -z "$_want" ]; then
            echo "error: $_rel is not pinned in scripts/schemas.sha256" >&2
            _bad=1
            continue
        fi
        _have=$(_schemas_digest "$_dir/$_rel")
        if [ "$_have" != "$_want" ]; then
            echo "error: $_rel does not match its pin" >&2
            echo "  pinned   $_want" >&2
            echo "  on disk  $_have" >&2
            _bad=1
        fi
    done
    return "$_bad"
}

# Every file the manifest pins, as relative paths.
pinned_schemas() {
    awk '{ print $2 }' "$BASE_DIR_FOR_SCHEMAS/scripts/schemas.sha256"
}
