# Sourced by the scripts that measure a number the README and the site quote.
#
# A count typed into prose drifts the day the thing it counts grows; the
# scripts that measure one are the only place that can notice. Each measures,
# then asks the two published pages to say exactly what it measured.

# claims_agree ROOT PHRASE — README.md and the site's verification page must
# both contain PHRASE verbatim. Fails naming the page that does not.
claims_agree() {
    root=$1
    phrase=$2
    ok=0
    for page in README.md site/content/docs/verification.md; do
        if ! grep -qF -- "$phrase" "$root/$page"; then
            echo "✗ $page does not say \"$phrase\" — update it to what was just measured" >&2
            ok=1
        fi
    done
    [ "$ok" -eq 0 ] && echo "✓ README.md and the site say \"$phrase\""
    return "$ok"
}

# claims_say ROOT PAGE PHRASE — one page must contain PHRASE verbatim: the prose
# restatements of a count, which are worded per page.
claims_say() {
    if grep -qF -- "$3" "$1/$2"; then
        echo "✓ $2 says \"$3\""
    else
        echo "✗ $2 does not say \"$3\" — update it to what was just measured" >&2
        return 1
    fi
}

# grouped N — 3760 as prose writes it, "3 760".
grouped() {
    printf '%s' "$1" | rev | sed 's/[0-9][0-9][0-9]/& /g' | rev | sed 's/^ //'
}
