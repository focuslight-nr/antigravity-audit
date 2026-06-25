#!/bin/zsh
# ANTIGRAVITY-AUDIT - Antigravity local security audit tool (macOS/Zsh)
# Read-only audit for ~/.gemini configuration, projects, trusted folders, and sensitive files.
setopt PIPE_FAIL KSH_ARRAYS BASH_REMATCH TYPESET_SILENT NULL_GLOB

VERSION="0.1.0"
SCRIPT_NAME="${0:t}"
GEMINI_DIR_NAME=".gemini"
HAS_JQ=false

AUDIT_USER=""
HOME_DIR=""
ANTIGRAVITY_DIR=""
TIMESTAMP=""
HOSTNAME_VAL=""

OPT_JSON=false
OPT_QUIET=false
OPT_HTML=""
OPT_ALL_USERS=false
OPT_REDACT_PATHS=false
OPT_FAIL_ON=""
OPT_OUTPUT=""
OPT_SUMMARY=false
OPT_ANTIGRAVITY_DIR=""

FINDING_SEV=()
FINDING_SECT=()
FINDING_MSG=()
FINDING_DET=()

TRUSTED_FOLDERS=()
PROJECTS=()
SKILLS=()
SENSITIVE_FILES=()
RETENTION_ITEMS=()

WARN_COUNT=0
INFO_COUNT=0
REVIEW_COUNT=0

preflight() {
    if [[ "$(uname -s 2>/dev/null)" != "Darwin" ]]; then
        print -r -- "ANTIGRAVITY-AUDIT currently supports macOS/Zsh only. Detected: $(uname -s 2>/dev/null || echo unknown)" >&2
        exit 1
    fi
    command -v jq >/dev/null 2>&1 && HAS_JQ=true || HAS_JQ=false
}

add_finding() {
    local sev="$1" sect="$2" msg="$3" det="${4:-}"
    FINDING_SEV+=("$sev")
    FINDING_SECT+=("$sect")
    FINDING_MSG+=("$msg")
    FINDING_DET+=("$det")
    case "$sev" in
        WARN) ((WARN_COUNT++)) ;;
        REVIEW) ((REVIEW_COUNT++)) ;;
        *) ((INFO_COUNT++)) ;;
    esac
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

jstr() {
    printf '"%s"' "$(json_escape "$1")"
}

display_text() {
    local s="$1"
    if [[ "$OPT_REDACT_PATHS" == "true" ]]; then
        [[ -n "$HOME_DIR" ]] && s="${s//${HOME_DIR}/~}"
        [[ -n "$AUDIT_USER" ]] && s="${s//\/Users\/${AUDIT_USER}/\/Users\/[USER]}"
    fi
    printf '%s' "$s"
}

jstr_out() {
    jstr "$(display_text "$1")"
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&#39;}"
    printf '%s' "$s"
}

html_out() {
    html_escape "$(display_text "$1")"
}

mask_email() {
    local email="$1"
    if [[ -z "$email" ]]; then
        printf ''
    elif [[ "$OPT_REDACT_PATHS" == "true" ]]; then
        printf '[REDACTED]'
    elif [[ "$email" == *"@"* ]]; then
        local name="${email%%@*}"
        local domain="${email#*@}"
        local masked=""
        if ((${#name} > 2)); then
            masked="${name[1,2]}$(printf '*%.0s' {3..${#name}})"
        else
            masked="${name}**"
        fi
        printf '%s@%s' "$masked" "$domain"
    else
        printf '%s' "$email"
    fi
}

fmt_bytes() {
    local n="$1"
    if ((n < 1024)); then printf '%d B' "$n"
    elif ((n < 1048576)); then printf '%.1f KB' "$((n / 1024.0))"
    elif ((n < 1073741824)); then printf '%.1f MB' "$((n / 1048576.0))"
    else printf '%.1f GB' "$((n / 1073741824.0))"; fi
}

file_mode() {
    local p="$1"
    stat -f '%Lp' "$p" 2>/dev/null || printf ''
}

dir_file_count() {
    local d="$1"
    [[ -d "$d" ]] || { printf '0'; return 0; }
    find "$d" -type f 2>/dev/null | wc -l | tr -d ' '
}

dir_total_bytes() {
    local d="$1"
    [[ -d "$d" ]] || { printf '0'; return 0; }
    find "$d" -type f -print0 2>/dev/null | xargs -0 stat -f '%z' 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

dir_latest_mtime() {
    local d="$1"
    [[ -d "$d" ]] || { printf ''; return 0; }
    find "$d" -type f -print0 2>/dev/null | xargs -0 stat -f '%m' 2>/dev/null | sort -nr | head -1 | while read -r ts; do
        [[ -n "$ts" ]] && date -r "$ts" '+%Y-%m-%dT%H:%M:%S%z'
    done
}

get_user_home() {
    local user="$1"
    if [[ -z "$user" || "$user" == "$(id -un)" ]]; then
        printf '%s' "$HOME"
        return 0
    fi
    if command -v dscl >/dev/null 2>&1; then
        dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
    fi
}

discover_gemini_users() {
    local user home
    if ! command -v dscl >/dev/null 2>&1; then
        for home in /Users/*; do
            [[ -d "$home/$GEMINI_DIR_NAME" ]] && basename "$home"
        done
        return
    fi
    dscl . -list /Users NFSHomeDirectory | while read -r user home; do
        [[ "$home" == /Users/* && -d "$home/$GEMINI_DIR_NAME" ]] && printf '%s\n' "$user"
    done
}

show_usage() {
    cat <<EOF
ANTIGRAVITY-AUDIT v$VERSION - Antigravity local security audit (macOS)
Usage: ./$SCRIPT_NAME [--html [FILE]] [--json] [--summary] [--output FILE]
       [--fail-on warn|review] [--redact-paths] [--user USER] [--all-users]
       [--antigravity-dir DIR] [-q|--quiet] [--version] [-h|--help]
EOF
}

# Argument parsing
while (($# > 0)); do
    case "$1" in
        --json) OPT_JSON=true; shift ;;
        --summary) OPT_SUMMARY=true; shift ;;
        --redact-paths) OPT_REDACT_PATHS=true; shift ;;
        --all-users) OPT_ALL_USERS=true; shift ;;
        -q|--quiet) OPT_QUIET=true; shift ;;
        --version) printf 'ANTIGRAVITY-AUDIT v%s\n' "$VERSION"; exit 0 ;;
        -h|--help) show_usage; exit 0 ;;
        --html)
            if (($# > 1)) && [[ ! "$2" =~ ^- ]]; then
                OPT_HTML="$2"
                shift 2
            else
                OPT_HTML="AUTO"
                shift
            fi
            ;;
        --output)
            if (($# < 2)); then printf 'Error: --output requires a file path\n' >&2; exit 1; fi
            OPT_OUTPUT="$2"
            shift 2
            ;;
        --fail-on)
            if (($# < 2)); then printf 'Error: --fail-on requires warn|review\n' >&2; exit 1; fi
            OPT_FAIL_ON="${2:l}"
            shift 2
            ;;
        --user)
            if (($# < 2)); then printf 'Error: --user requires a username\n' >&2; exit 1; fi
            AUDIT_USER="$2"
            shift 2
            ;;
        --antigravity-dir)
            if (($# < 2)); then printf 'Error: --antigravity-dir requires a directory\n' >&2; exit 1; fi
            OPT_ANTIGRAVITY_DIR="$2"
            shift 2
            ;;
        *)
            printf 'Error: Unknown option %s\n' "$1" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

# Validate options
[[ "$OPT_JSON" == "true" && -n "$OPT_HTML" ]] && { printf 'Error: --json and --html are mutually exclusive\n' >&2; exit 1; }
[[ "$OPT_ALL_USERS" == "true" && -n "$AUDIT_USER" ]] && { printf 'Error: --user and --all-users are mutually exclusive\n' >&2; exit 1; }
[[ "$OPT_ALL_USERS" == "true" && -n "$OPT_ANTIGRAVITY_DIR" ]] && { printf 'Error: --antigravity-dir and --all-users are mutually exclusive\n' >&2; exit 1; }
[[ -n "$OPT_ANTIGRAVITY_DIR" && ! -d "$OPT_ANTIGRAVITY_DIR" ]] && { printf 'Error: --antigravity-dir is not a directory: %s\n' "$OPT_ANTIGRAVITY_DIR" >&2; exit 1; }
[[ -z "$OPT_HTML" && "$OPT_OUTPUT" == *.html ]] && { printf 'Error: --output .html requires --html\n' >&2; exit 1; }
[[ -n "$OPT_FAIL_ON" && "$OPT_FAIL_ON" != "warn" && "$OPT_FAIL_ON" != "review" ]] && { printf "Error: --fail-on must be 'warn' or 'review'\n" >&2; exit 1; }

get_file_broad_summary() {
    local p="$1"
    [[ -f "$p" ]] || return
    local mode owner group broad=0
    mode=$(file_mode "$p")
    owner=$(stat -f '%Su' "$p" 2>/dev/null || echo "?")
    group=$(stat -f '%Sg' "$p" 2>/dev/null || echo "?")
    # Check if world readable/writable/executable or group writable
    if [[ -n "$mode" ]]; then
        # Last digit > 0 (world permissions) or middle digit matches write (group writable)
        local world="${mode: -1}"
        local grp="${mode: -2:1}"
        if ((world > 0 || grp == 2 || grp == 3 || grp == 6 || grp == 7)); then
            broad=1
        fi
    fi
    printf 'mode=%s owner=%s group=%s broad=%d' "$mode" "$owner" "$group" "$broad"
}

add_sensitive_file() {
    local name="$1" p="$2" broad_sev="${3:-}"
    [[ -f "$p" ]] || return
    local summary broad=0
    summary=$(get_file_broad_summary "$p")
    [[ "$summary" =~ 'broad=1' ]] && broad=1
    # Strip broad suffix for display
    summary="${summary% broad=*}"
    SENSITIVE_FILES+=("$name|$summary|$p")
    if [[ -n "$broad_sev" && "$broad" -eq 1 ]]; then
        add_finding "$broad_sev" "Sensitive Files" "$name has broad permissions" "$summary; path=$p"
    fi
}

parse_skill_frontmatter() {
    local p="$1" fallback
    fallback="$(basename "$(dirname "$p")")"
    [[ -f "$p" ]] || { printf '%s||' "$fallback"; return 0; }
    local name="" desc="" in_desc=false line
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}" # trim leading
        line="${line%"${line##*[![:space:]]}"}" # trim trailing
        if [[ "$line" == "---" && ( -n "$name" || -n "$desc" ) ]]; then break; fi
        if [[ "$line" == name:* ]]; then
            name="${line#name:}"
            name="${name#"${name%%[![:space:]]*}"}"
            name="${name#\"}"; name="${name%\"}"
            name="${name#\'}"; name="${name%\'}"
            in_desc=false
        elif [[ "$line" == description:* ]]; then
            desc="${line#description:}"
            desc="${desc#"${desc%%[![:space:]]*}"}"
            desc="${desc#\"}"; desc="${desc%\"}"
            desc="${desc#\'}"; desc="${desc%\'}"
            if [[ "$desc" == ">" || "$desc" == "|" ]]; then desc=""; fi
            in_desc=true
        elif [[ "$in_desc" == "true" && "$line" == "  "* ]]; then
            desc="$desc ${line#  }"
        elif [[ "$line" != "---" ]]; then
            in_desc=false
        fi
    done < "$p"
    [[ -z "$name" ]] && name="$fallback"
    printf '%s|%s|%s' "$name" "$desc" "$p"
}

collect_customizations() {
    local config_dir="$1" source="$2" file parsed name desc path scripts_dir script_count
    local skills_dir="$config_dir/skills"
    if [[ -d "$skills_dir" ]]; then
        for file in "$skills_dir"/**/SKILL.md; do
            [[ -f "$file" ]] || continue
            parsed=$(parse_skill_frontmatter "$file")
            name="${parsed%%|*}"
            local rest="${parsed#*|}"
            desc="${rest%%|*}"
            path="${rest#*|}"
            SKILLS+=("$source|$name|$desc|$path")
            
            # Check for helper scripts
            scripts_dir="$(dirname "$file")/scripts"
            if [[ -d "$scripts_dir" ]]; then
                script_count=$(find "$scripts_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
                if ((script_count > 0)); then
                    add_finding "REVIEW" "Skills" "Skill '$name' contains custom script files ($script_count)" "source=$source; folder=$scripts_dir"
                fi
            fi
        done
    fi
    local agents_md="$config_dir/AGENTS.md"
    if [[ -f "$agents_md" ]]; then
        add_finding "INFO" "Skills" "Custom system rules defined in AGENTS.md" "source=$source; path=$agents_md"
    fi
}

collect_main_config() {
    local settings="$ANTIGRAVITY_DIR/settings.json"
    if [[ -f "$settings" ]]; then
        add_sensitive_file "settings.json" "$settings" "REVIEW"
        if [[ "$HAS_JQ" == "true" ]]; then
            local model theme retention_enabled max_age
            model=$(jq -r '.model.name // ""' "$settings" 2>/dev/null)
            theme=$(jq -r '.theme // ""' "$settings" 2>/dev/null)
            retention_enabled=$(jq -r '.general.sessionRetention.enabled // ""' "$settings" 2>/dev/null)
            max_age=$(jq -r '.general.sessionRetention.maxAge // ""' "$settings" 2>/dev/null)
            [[ -n "$model" ]] && add_finding "INFO" "Config" "Default model: $model"
            [[ -n "$theme" ]] && add_finding "INFO" "Config" "Theme: $theme"
            [[ -n "$retention_enabled" ]] && add_finding "INFO" "Config" "Session retention enabled=$retention_enabled; maxAge=$max_age"
        fi
    else
        add_finding "INFO" "Config" "settings.json not found" "$settings"
    fi
}

collect_projects() {
    local projects="$ANTIGRAVITY_DIR/projects.json"
    if [[ -f "$projects" ]]; then
        add_sensitive_file "projects.json" "$projects" "REVIEW"
        if [[ "$HAS_JQ" == "true" ]]; then
            local keys path name has_agents
            keys=$(jq -r '.projects | keys[]' "$projects" 2>/dev/null) || return
            while read -r path; do
                [[ -z "$path" ]] && continue
                name=$(jq -r --arg p "$path" '.projects[$p]' "$projects" 2>/dev/null)
                has_agents="false"
                if [[ -d "$path" ]]; then
                    local agents_dir="$path/.agents"
                    if [[ -d "$agents_dir" ]]; then
                        has_agents="true"
                        collect_customizations "$agents_dir" "workspace:$name"
                    fi
                fi
                PROJECTS+=("$path|$name|$has_agents")
            done <<< "$keys"
            ((${#PROJECTS[@]} > 0)) && add_finding "INFO" "Projects" "${#PROJECTS[@]} project(s) registered"
        fi
    fi
}

collect_trusted_folders() {
    local trusted="$ANTIGRAVITY_DIR/trustedFolders.json"
    if [[ -f "$trusted" ]]; then
        add_sensitive_file "trustedFolders.json" "$trusted" "REVIEW"
        if [[ "$HAS_JQ" == "true" ]]; then
            local keys path level summary
            keys=$(jq -r 'keys[]' "$trusted" 2>/dev/null) || return
            while read -r path; do
                [[ -z "$path" ]] && continue
                level=$(jq -r --arg p "$path" '.[$p]' "$trusted" 2>/dev/null)
                summary=$(get_file_broad_summary "$path")
                # Remove broad= suffix
                summary="${summary% broad=*}"
                TRUSTED_FOLDERS+=("$path|$level|$summary")
                add_finding "WARN" "Trusted Folders" "Trusted folder grants Antigravity broader workspace autonomy" "path=$path; trust=$level"
            done <<< "$keys"
            ((${#TRUSTED_FOLDERS[@]} > 0)) && add_finding "INFO" "Trusted Folders" "${#TRUSTED_FOLDERS[@]} trusted folder(s) configured"
        fi
    fi
}

collect_accounts() {
    local accounts="$ANTIGRAVITY_DIR/google_accounts.json"
    if [[ -f "$accounts" ]]; then
        add_sensitive_file "google_accounts.json" "$accounts" "REVIEW"
        if [[ "$HAS_JQ" == "true" ]]; then
            local active masked
            active=$(jq -r '.active // ""' "$accounts" 2>/dev/null)
            if [[ -n "$active" ]]; then
                masked=$(mask_email "$active")
                add_finding "INFO" "Accounts" "Active Google Account: $masked"
            fi
        fi
    fi
}

add_retention_dir() {
    local name="$1" dir="$2" limit="${3:-104857600}"
    [[ -d "$dir" ]] || return
    local count bytes latest
    count=$(dir_file_count "$dir")
    bytes=$(dir_total_bytes "$dir")
    latest=$(dir_latest_mtime "$dir")
    RETENTION_ITEMS+=("$name|$count|$bytes|$latest|$dir")
    add_finding "INFO" "Retention" "$name contains $count file(s)" "size=$(fmt_bytes "$bytes"); latest=${latest:-none}"
    ((bytes > limit)) && add_finding "REVIEW" "Retention" "$name retained data is larger than $(fmt_bytes "$limit")" "$(fmt_bytes "$bytes")"
    ((count > 1000)) && add_finding "REVIEW" "Retention" "$name contains more than 1000 files" "$count files"
}

collect_retention() {
    add_retention_dir "history" "$ANTIGRAVITY_DIR/history" 209715200 # 200MB
    add_retention_dir "tmp" "$ANTIGRAVITY_DIR/tmp" 209715200 # 200MB
    local brain_dir="$ANTIGRAVITY_DIR/antigravity/brain"
    [[ -d "$brain_dir" ]] && add_retention_dir "antigravity-brain" "$brain_dir" 524288000 # 500MB
}

collect_runtime() {
    local count
    count=$(pgrep -f 'antigravity|gemini' 2>/dev/null | wc -l | tr -d ' ')
    if ((count > 0)); then
        add_finding "INFO" "Runtime" "Active antigravity/gemini process(es) detected: $count"
    fi
}

json_split_field() {
    local s="$1" field="$2"
    local IFS="|"
    local parts=(${(s:|:)s})
    printf '%s' "${parts[$field]}"
}

render_json() {
    local findings="[" idx=0 i
    for ((i=1; i<=${#FINDING_SEV[@]}; i++)); do
        ((idx > 0)) && findings+=","
        findings+="{\"severity\":$(jstr "${FINDING_SEV[$i]}"),\"section\":$(jstr "${FINDING_SECT[$i]}"),\"message\":$(jstr_out "${FINDING_MSG[$i]}"),\"detail\":$(jstr_out "${FINDING_DET[$i]}")}"
        ((idx++))
    done
    findings+="]"

    local tf="[" idx=0
    for row in "${TRUSTED_FOLDERS[@]}"; do
        ((idx > 0)) && tf+=","
        tf+="{\"path\":$(jstr_out "$(json_split_field "$row" 1)"),\"trust_level\":$(jstr "$(json_split_field "$row" 2)"),\"acl\":$(jstr "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    tf+="]"

    local projects="[" idx=0
    for row in "${PROJECTS[@]}"; do
        ((idx > 0)) && projects+=","
        projects+="{\"path\":$(jstr_out "$(json_split_field "$row" 1)"),\"name\":$(jstr "$(json_split_field "$row" 2)"),\"has_agents_dir\":$(jstr "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    projects+="]"

    local skills="[" idx=0
    for row in "${SKILLS[@]}"; do
        ((idx > 0)) && skills+=","
        skills+="{\"source\":$(jstr "$(json_split_field "$row" 1)"),\"name\":$(jstr "$(json_split_field "$row" 2)"),\"description\":$(jstr "$(json_split_field "$row" 3)"),\"path\":$(jstr_out "$(json_split_field "$row" 4)")}"
        ((idx++))
    done
    skills+="]"

    local sens_files="[" idx=0
    for row in "${SENSITIVE_FILES[@]}"; do
        ((idx > 0)) && sens_files+=","
        sens_files+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"mode\":$(jstr "$(json_split_field "$row" 2)"),\"path\":$(jstr_out "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    sens_files+="]"

    local retention="[" idx=0
    for row in "${RETENTION_ITEMS[@]}"; do
        ((idx > 0)) && retention+=","
        retention+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"file_count\":$(jstr "$(json_split_field "$row" 2)"),\"bytes\":$(jstr "$(json_split_field "$row" 3)"),\"latest_mtime\":$(jstr "$(json_split_field "$row" 4)"),\"path\":$(jstr_out "$(json_split_field "$row" 5)")}"
        ((idx++))
    done
    retention+="]"

    printf '{"timestamp":%s,"hostname":%s,"username":%s,"antigravity_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d},"findings":%s,"trusted_folders":%s,"projects":%s,"skills":%s,"sensitive_files":%s,"retention":%s}' \
        "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$ANTIGRAVITY_DIR")" \
        "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$findings" "$tf" \
        "$projects" "$skills" "$sens_files" "$retention"
}

html_rows_findings() {
    local i
    for ((i=1; i<=${#FINDING_SEV[@]}; i++)); do
        [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
        printf '<tr><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n' \
            "$(html_escape "${(L)FINDING_SEV[$i]}")" "$(html_escape "${FINDING_SEV[$i]}")" "$(html_escape "${FINDING_SECT[$i]}")" "$(html_out "${FINDING_MSG[$i]}")" "$(html_out "${FINDING_DET[$i]}")"
    done
}

render_html_body() {
    cat <<EOF
<section class="report">
<h1>ANTIGRAVITY-AUDIT</h1>
<p class="meta">User: <strong>$(html_out "$AUDIT_USER")</strong> · Host: <strong>$(html_escape "$HOSTNAME_VAL")</strong> · Generated: <strong>$(html_escape "$TIMESTAMP")</strong></p>
<p class="meta">Antigravity home: <code>$(html_out "$ANTIGRAVITY_DIR")</code></p>
<div class="summary">
  <div><span>WARN</span><strong>$WARN_COUNT</strong></div>
  <div><span>REVIEW</span><strong>$REVIEW_COUNT</strong></div>
  <div><span>INFO</span><strong>$INFO_COUNT</strong></div>
</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead>
<tbody>
$(html_rows_findings)
</tbody>
</table>
</section>
EOF
}

render_html() {
    cat <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ANTIGRAVITY-AUDIT Report</title>
<style>
body{margin:0;background:#0d1117;color:#e6edf3;font-family:"Segoe UI",sans-serif}
main{max-width:1180px;margin:auto;padding:32px 20px}
h2{margin-top:28px}
.meta{color:#8b949e}
.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}
.summary div{background:#161b22;border:1px solid #30363d;padding:12px}
.summary span{display:block;color:#8b949e}
.summary strong{font-size:24px}
table{width:100%;border-collapse:collapse;border:1px solid #30363d}
th,td{padding:9px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top;font-size:13px}
th{color:#8b949e;background:#161b22}
code{color:#cae8ff;white-space:pre-wrap;word-break:break-word}
.badge{padding:2px 6px;font-weight:700}
.warn{background:#5c1f1f;color:#ffa198}
.review{background:#3d2f00;color:#f0c846}
.info{background:#0c2a4a;color:#79c0ff}
</style>
</head>
<body>
<main>
$(render_html_body)
</main>
</body>
</html>
EOF
}

write_terminal_report() {
    local i summary_text shown
    if [[ "$OPT_SUMMARY" == "true" ]]; then
        printf '%s  WARN=%d REVIEW=%d INFO=%d  %s\n' "$(display_text "$AUDIT_USER")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$(display_text "$ANTIGRAVITY_DIR")"
        shown=0
        for ((i=1; i<=${#FINDING_SEV[@]}; i++)); do
            [[ "${FINDING_SEV[$i]}" == "INFO" ]] && continue
            printf '  [%s] %s: %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
            ((shown++))
            ((shown >= 8)) && break
        done
        return
    fi

    printf '\nANTIGRAVITY-AUDIT v%s - Antigravity local security audit (macOS)\n' "$VERSION"
    printf 'User: %s\n' "$(display_text "$AUDIT_USER")"
    printf 'Antigravity home: %s\n' "$(display_text "$ANTIGRAVITY_DIR")"
    printf 'Findings: WARN=%d REVIEW=%d INFO=%d\n\n' "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT"

    if [[ "$OPT_QUIET" != "true" || "$WARN_COUNT" -gt 0 || "$REVIEW_COUNT" -gt 0 ]]; then
        print -r -- 'Findings'
        for ((i=1; i<=${#FINDING_SEV[@]}; i++)); do
            [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
            printf '  [%s] %-16s %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
            [[ -n "${FINDING_DET[$i]}" ]] && printf '       %s\n' "$(display_text "${FINDING_DET[$i]}")"
        done
        printf '\n'
    fi

    # Trusted Folders
    print -r -- 'Trusted Folders'
    if ((${#TRUSTED_FOLDERS[@]} == 0)); then print -r -- '  none'; else
        for row in "${TRUSTED_FOLDERS[@]}"; do
            printf '  %-22s trust=%s acl=%s\n' "$(display_text "$(json_split_field "$row" 1)")" "$(json_split_field "$row" 2)" "$(json_split_field "$row" 3)"
        done
    fi
    printf '\n'

    # Projects
    print -r -- 'Projects'
    if ((${#PROJECTS[@]} == 0)); then print -r -- '  none'; else
        for row in "${PROJECTS[@]}"; do
            printf '  %-22s name=%s has_agents_dir=%s\n' "$(display_text "$(json_split_field "$row" 1)")" "$(json_split_field "$row" 2)" "$(json_split_field "$row" 3)"
        done
    fi
    printf '\n'

    # Skills
    print -r -- 'Skills'
    if ((${#SKILLS[@]} == 0)); then print -r -- '  none'; else
        for row in "${SKILLS[@]}"; do
            printf '  %-22s source=%s desc=%s\n' "$(display_text "$(json_split_field "$row" 2)")" "$(json_split_field "$row" 1)" "$(display_text "$(json_split_field "$row" 3)")"
        done
    fi
    printf '\n'

    # Sensitive Files
    print -r -- 'Sensitive Files'
    if ((${#SENSITIVE_FILES[@]} == 0)); then print -r -- '  none'; else
        for row in "${SENSITIVE_FILES[@]}"; do
            printf '  %-22s mode=%s path=%s\n' "$(json_split_field "$row" 1)" "$(json_split_field "$row" 2)" "$(display_text "$(json_split_field "$row" 3)")"
        done
    fi
    printf '\n'

    # Retention
    print -r -- 'Retention'
    if ((${#RETENTION_ITEMS[@]} == 0)); then print -r -- '  none'; else
        for row in "${RETENTION_ITEMS[@]}"; do
            printf '  %-22s files=%s size=%s latest=%s path=%s\n' "$(json_split_field "$row" 1)" "$(json_split_field "$row" 2)" "$(fmt_bytes "$(json_split_field "$row" 3)")" "$(json_split_field "$row" 4)" "$(display_text "$(json_split_field "$row" 5)")"
        done
    fi
    printf '\n'
}

run_user_audit() {
    local user="$1" home="$2"
    AUDIT_USER="$user"
    HOME_DIR="$home"
    if [[ -n "$OPT_ANTIGRAVITY_DIR" ]]; then
        ANTIGRAVITY_DIR="$OPT_ANTIGRAVITY_DIR"
        HOME_DIR="$(dirname "$ANTIGRAVITY_DIR")"
    else
        ANTIGRAVITY_DIR="$HOME_DIR/$GEMINI_DIR_NAME"
    fi

    if [[ ! -d "$ANTIGRAVITY_DIR" ]]; then
        add_finding "INFO" "General" "Antigravity data not found" "$ANTIGRAVITY_DIR"
        collect_runtime
        return 0
    fi

    collect_main_config
    collect_projects
    collect_trusted_folders
    collect_accounts

    # Collect global customizations
    local global_config="$ANTIGRAVITY_DIR/config"
    [[ -d "$global_config" ]] && collect_customizations "$global_config" "global"

    # Sensitive files
    add_sensitive_file "oauth_creds.json" "$ANTIGRAVITY_DIR/oauth_creds.json" "WARN"
    add_sensitive_file "installation_id" "$ANTIGRAVITY_DIR/installation_id" "REVIEW"
    add_sensitive_file "user_id" "$ANTIGRAVITY_DIR/user_id" "REVIEW"

    collect_retention
    collect_runtime
}

# --- Execution ---
preflight

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname)

# Collect targets
declare -A targets
if [[ "$OPT_ALL_USERS" == "true" ]]; then
    if [[ "$UID" -ne 0 ]]; then
        printf 'Error: --all-users requires root privileges (sudo).\n' >&2
        exit 1
    fi
    discover_gemini_users | while read -r user; do
        targets[$user]=$(get_user_home "$user")
    done
else
    local target_user="${AUDIT_USER:-$(id -un)}"
    local target_home
    target_home=$(get_user_home "$target_user")
    if [[ -z "$target_home" ]]; then
        printf 'Error: Could not resolve home directory for user %s\n' "$target_user" >&2
        exit 1
    fi
    targets[$target_user]="$target_home"
fi

if ((${#targets} == 0)); then
    printf 'No users with Antigravity data found.\n' >&2
    exit 1
fi

# Run audits
# We currently do output for the single targeted user. If multiple users targeted, we loop.
# In single target or first target user:
local first_user=("${(@k)targets}")
first_user="${first_user[1]}"
local first_home="${targets[$first_user]}"

run_user_audit "$first_user" "$first_home"

# Generate report
local content=""
if [[ "$OPT_JSON" == "true" ]]; then
    content=$(render_json)
elif [[ -n "$OPT_HTML" ]]; then
    content=$(render_html)
else
    content=$(write_terminal_report)
fi

# Output logic
if [[ -n "$OPT_HTML" ]]; then
    local path="$OPT_HTML"
    if [[ "$path" == "AUTO" ]]; then
        path="antigravity_audit_$(date '+%Y%m%d_%H%M%S').html"
    fi
    printf '%s' "$content" > "$path"
    printf 'HTML report written: %s\n' "$path"
elif [[ -n "$OPT_OUTPUT" ]]; then
    printf '%s' "$content" > "$OPT_OUTPUT"
else
    printf '%s' "$content"
fi

# Exit code logic
local exit_code=0
if [[ "$OPT_FAIL_ON" == "warn" && "$WARN_COUNT" -gt 0 ]]; then
    exit_code=2
elif [[ "$OPT_FAIL_ON" == "review" && ( "$REVIEW_COUNT" -gt 0 || "$WARN_COUNT" -gt 0 ) ]]; then
    exit_code=1
fi

exit $exit_code
