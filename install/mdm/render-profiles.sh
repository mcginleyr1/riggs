#!/usr/bin/env bash
# Fills the @...@ placeholders of the profile templates and writes the copies you deploy. The
# templates themselves are never deployed: an MDM accepts a literal @TEAM_ID@ without complaint.
# A copy that would still contain a placeholder is not written, and the script exits non-zero.
set -euo pipefail

MDM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: install/mdm/render-profiles.sh --out DIR [values] [template ...]

Values (each fills the placeholder of the same name; XML-escaped for you):
  --organization TEXT          @ORGANIZATION@
  --team-id ID                 @TEAM_ID@
  --filter-requirement TEXT    @FILTER_EXTENSION_DESIGNATED_REQUIREMENT@
  --daemon-requirement TEXT    @DAEMON_CODE_REQUIREMENT@
  --update-url URL             @UPDATE_MANIFEST_URL@

Templates (file names in install/mdm/, default: all of them): render only the ones you use,
for example `riggs-network-filter.mobileconfig riggs-full-disk-access.mobileconfig`.
EOF
}

OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --organization) export RIGGS_ORGANIZATION="$2"; shift 2 ;;
        --team-id) export RIGGS_TEAM_ID="$2"; shift 2 ;;
        --filter-requirement) export RIGGS_FILTER_EXTENSION_DESIGNATED_REQUIREMENT="$2"; shift 2 ;;
        --daemon-requirement) export RIGGS_DAEMON_CODE_REQUIREMENT="$2"; shift 2 ;;
        --update-url) export RIGGS_UPDATE_MANIFEST_URL="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "unknown argument: $1" >&2; usage >&2; exit 1 ;;
        *) break ;;
    esac
done
[[ -n "$OUT" ]] || { usage >&2; exit 1; }

if [[ $# -gt 0 ]]; then
    templates=("$@")
else
    templates=("$MDM_DIR"/*.mobileconfig)
fi
mkdir -p "$OUT"

status=0
for template in "${templates[@]}"; do
    name="$(basename "$template")"
    source_file="$MDM_DIR/$name"
    [[ -f "$source_file" ]] || { echo "no such template: $name" >&2; status=1; continue; }
    result="$OUT/$name"
    rm -f "$result"

    # Comments are dropped: they name the placeholders, and a filled-in value must not land in one.
    perl -0pe '
        sub esc { my $s = shift; $s =~ s{&}{&amp;}g; $s =~ s{<}{&lt;}g; $s =~ s{>}{&gt;}g; $s }
        s{<!--.*?-->\s*}{}gs;
        s{@([A-Z_]+)@}{ exists $ENV{"RIGGS_$1"} ? esc($ENV{"RIGGS_$1"}) : "\@$1\@" }ge;
    ' "$source_file" > "$result.partial"

    left=$(grep -o '@[A-Z_]*@' "$result.partial" | sort -u | tr '\n' ' ' || true)
    if [[ -n "$left" ]]; then
        echo "NOT WRITTEN $name: no value for $left" >&2
        rm -f "$result.partial"
        status=1
        continue
    fi
    if ! plutil -lint "$result.partial" >/dev/null; then
        echo "NOT WRITTEN $name: plutil -lint failed" >&2
        rm -f "$result.partial"
        status=1
        continue
    fi
    mv "$result.partial" "$result"
    echo "wrote $result"
done
exit "$status"
