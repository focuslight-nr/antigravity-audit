#!/bin/zsh
# ANTIGRAVITY-AUDIT - Antigravity local security audit tool (macOS/Zsh)
# Read-only audit for ~/.gemini configuration, MCP servers, hooks, plugins, projects, trusted folders, security policies, and sensitive files.
setopt PIPE_FAIL KSH_ARRAYS BASH_REMATCH TYPESET_SILENT NULL_GLOB

VERSION="0.2.0"
SCRIPT_NAME="${0:t}"
GEMINI_DIR_NAME=".gemini"
DANGEROUS_MCP_HINTS="bash sh zsh python python3 node ruby perl osascript sqlite3 psql mysql curl wget nc ncat ssh scp"
SENSITIVE_NAME_RE='(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)'
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
OPT_DIFF=""
OPT_DIFF_JSON=false
OPT_FAIL_ON=""
OPT_OUTPUT=""
OPT_SUMMARY=false
OPT_ANTIGRAVITY_DIR=""

FINDING_SEV=()
FINDING_SECT=()
FINDING_MSG=()
FINDING_DET=()

MCP_NAMES=()
declare -A MCP_CMDS MCP_ARGS MCP_ENVKEYS MCP_SOURCE MCP_TYPE

HOOKS=()
PLUGINS=()
SECURITY_SETTINGS=()
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

reset_state() {
    FINDING_SEV=()
    FINDING_SECT=()
    FINDING_MSG=()
    FINDING_DET=()
    MCP_NAMES=()
    MCP_CMDS=()
    MCP_ARGS=()
    MCP_ENVKEYS=()
    MCP_SOURCE=()
    MCP_TYPE=()
    HOOKS=()
    PLUGINS=()
    SECURITY_SETTINGS=()
    TRUSTED_FOLDERS=()
    PROJECTS=()
    SKILLS=()
    SENSITIVE_FILES=()
    RETENTION_ITEMS=()
    WARN_COUNT=0
    INFO_COUNT=0
    REVIEW_COUNT=0
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

strip_quotes() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    s="${s#\"}"
    s="${s%\"}"
    s="${s#\'}"
    s="${s%\'}"
    printf '%s' "$s"
}

redact_value() {
    local key="$1" val="$2"
    if [[ "${(L)key}" =~ "$SENSITIVE_NAME_RE" || "${(L)val}" =~ '(bearer |token=|secret=|password=|api[_-]?key=)' ]]; then
        printf '[REDACTED]'
    else
        printf '%s' "$val"
    fi
}

mcp_env_risk_tags() {
    local keys="$1" tags=() k
    for k in ${(s:,:)keys}; do
        [[ -z "$k" ]] && continue
        if [[ "${(L)k}" =~ "$SENSITIVE_NAME_RE" ]]; then
            tags+=("contains-sensitive-env")
            break
        fi
    done
    local IFS=","
    printf '%s' "${tags[*]}"
}

hook_risk_tags() {
    local cmd="$1" tags=() lower
    lower="${(L)cmd}"
    [[ "$lower" == *"curl "* || "$lower" == *"wget "* || "$lower" == *"nc "* || "$lower" == *"fetch "* ]] && tags+=("network-access")
    [[ "$lower" == *"rm -rf"* || "$lower" == *"rm "* || "$lower" == *"git reset"* || "$lower" == *"git clean"* ]] && tags+=("destructive")
    [[ "$lower" == *"sudo "* || "$lower" == *"chmod "* || "$lower" == *"chown "* ]] && tags+=("privileged")
    [[ "$lower" == *"eval "* || "$lower" == *"exec "* || "$lower" == *"sh -c"* || "$lower" == *"bash -c"* ]] && tags+=("dynamic-code-execution")
    local IFS=","
    printf '%s' "${tags[*]}"
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
            masked="${name:0:2}$(printf '*%.0s' {3..${#name}})"
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
       [--diff BASELINE.json] [--diff-json] [--fail-on warn|review]
       [--redact-paths] [--user USER] [--all-users] [--antigravity-dir DIR]
       [-q|--quiet] [--version] [-h|--help]
EOF
}

# Argument parsing
while (($# > 0)); do
    case "$1" in
        --json) OPT_JSON=true; shift ;;
        --diff)
            if (($# < 2)); then printf 'Error: --diff requires a baseline JSON file\n' >&2; exit 1; fi
            OPT_DIFF="$2"
            shift 2
            ;;
        --diff-json) OPT_DIFF_JSON=true; shift ;;
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
if [[ -n "$OPT_DIFF" && -n "$OPT_HTML" ]]; then
    printf 'Error: --diff and --html are mutually exclusive\n' >&2
    exit 1
fi
if [[ -n "$OPT_DIFF" && "$OPT_JSON" == "true" && "$OPT_DIFF_JSON" != "true" ]]; then
    printf 'Error: --diff and --json are mutually exclusive; use --diff-json for JSON diff output\n' >&2
    exit 1
fi
if [[ "$OPT_DIFF_JSON" == "true" && -z "$OPT_DIFF" ]]; then
    printf 'Error: --diff-json requires --diff BASELINE.json\n' >&2
    exit 1
fi
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

collect_mcp_file() {
    local file="$1" source="$2"
    [[ -f "$file" ]] || return
    add_sensitive_file "$(basename "$file")" "$file" "REVIEW"
    if [[ "$HAS_JQ" != "true" ]]; then
        add_finding "INFO" "MCP Servers" "MCP config found at $file (jq not available to inspect)" "source=$source"
        return
    fi

    local names
    names=$(jq -r '.mcpServers | keys[]?' "$file" 2>/dev/null) || return
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local cmd args url env_keys env_risk
        cmd=$(jq -r --arg n "$name" '.mcpServers[$n].command // ""' "$file" 2>/dev/null)
        args=$(jq -r --arg n "$name" '(.mcpServers[$n].args // []) | join(" ")' "$file" 2>/dev/null)
        url=$(jq -r --arg n "$name" '.mcpServers[$n].serverUrl // ""' "$file" 2>/dev/null)
        env_keys=$(jq -r --arg n "$name" '(.mcpServers[$n].env // {}) | keys | join(",")' "$file" 2>/dev/null)

        MCP_NAMES+=("$name")
        MCP_SOURCE[$name]="$source"
        if [[ -n "$url" ]]; then
            MCP_TYPE[$name]="sse"
            MCP_CMDS[$name]="$url"
            MCP_ARGS[$name]=""
            MCP_ENVKEYS[$name]=""
            if [[ "$url" == http://* ]]; then
                add_finding "WARN" "MCP Servers" "Unencrypted SSE MCP server: $name" "url=$url; source=$source"
            else
                add_finding "REVIEW" "MCP Servers" "Remote SSE MCP server configured: $name" "url=$url; source=$source"
            fi
        else
            MCP_TYPE[$name]="stdio"
            MCP_CMDS[$name]="$cmd"
            MCP_ARGS[$name]="$args"
            MCP_ENVKEYS[$name]="$env_keys"

            local cmd_base="${cmd:t}"
            local is_dangerous=false
            for hint in ${(z)DANGEROUS_MCP_HINTS}; do
                if [[ "$cmd_base" == "$hint" || "$cmd" == *"/$hint" ]]; then
                    is_dangerous=true
                    break
                fi
            done

            env_risk="$(mcp_env_risk_tags "$env_keys")"
            if [[ "$is_dangerous" == "true" ]]; then
                add_finding "WARN" "MCP Servers" "MCP server executes broad command runner: $name" "cmd=$cmd $args; source=$source"
            else
                add_finding "REVIEW" "MCP Servers" "Local MCP server configured: $name" "cmd=$cmd $args; source=$source"
            fi
            if [[ -n "$env_risk" ]]; then
                add_finding "REVIEW" "MCP Servers" "MCP server has sensitive environment variables: $name" "keys=$env_keys; source=$source"
            fi
        fi
    done <<< "$names"
}

collect_hooks_file() {
    local file="$1" source="$2"
    [[ -f "$file" ]] || return
    add_sensitive_file "$(basename "$file")" "$file" "REVIEW"
    if [[ "$HAS_JQ" != "true" ]]; then
        add_finding "INFO" "Hooks" "Hooks config found at $file (jq not available to inspect)" "source=$source"
        return
    fi

    local hook_names
    hook_names=$(jq -r 'keys[]?' "$file" 2>/dev/null) || return
    while IFS= read -r hname; do
        [[ -z "$hname" ]] && continue
        local enabled
        enabled=$(jq -r --arg n "$hname" 'if .[$n].enabled != null then .[$n].enabled | tostring else "true" end' "$file" 2>/dev/null)
        
        # Tool events (PreToolUse, PostToolUse) - Grouped with matcher
        for ev in PreToolUse PostToolUse; do
            local count
            count=$(jq -r --arg n "$hname" --arg ev "$ev" '(.[$n][$ev] // []) | length' "$file" 2>/dev/null)
            if ((count > 0)); then
                for ((idx=0; idx<count; idx++)); do
                    local matcher hcount
                    matcher=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" '.[$n][$ev][$i].matcher // "*"' "$file" 2>/dev/null)
                    hcount=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" '(.[$n][$ev][$i].hooks // []) | length' "$file" 2>/dev/null)
                    for ((hidx=0; hidx<hcount; hidx++)); do
                        local htype hcmd htimeout
                        htype=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" --argjson hi "$hidx" '.[$n][$ev][$i].hooks[$hi].type // "command"' "$file" 2>/dev/null)
                        hcmd=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" --argjson hi "$hidx" '.[$n][$ev][$i].hooks[$hi].command // ""' "$file" 2>/dev/null)
                        htimeout=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" --argjson hi "$hidx" '.[$n][$ev][$i].hooks[$hi].timeout // "30"' "$file" 2>/dev/null)
                        
                        HOOKS+=("$hname|$ev|$matcher|$htype|$hcmd|$enabled|$source|$htimeout")
                        if [[ "$enabled" == "true" ]]; then
                            local rtags
                            rtags="$(hook_risk_tags "$hcmd")"
                            if [[ "$rtags" == *"network-access"* || "$rtags" == *"destructive"* || "$rtags" == *"privileged"* ]]; then
                                add_finding "WARN" "Hooks" "High-risk lifecycle hook command ($ev): $hname" "cmd=$hcmd; tags=$rtags; source=$source"
                            else
                                add_finding "REVIEW" "Hooks" "Lifecycle hook command configured ($ev): $hname" "cmd=$hcmd; matcher=$matcher; source=$source"
                            fi
                        fi
                    done
                done
            fi
        done

        # Flat events (PreInvocation, PostInvocation, Stop)
        for ev in PreInvocation PostInvocation Stop; do
            local count
            count=$(jq -r --arg n "$hname" --arg ev "$ev" '(.[$n][$ev] // []) | length' "$file" 2>/dev/null)
            if ((count > 0)); then
                for ((idx=0; idx<count; idx++)); do
                    local htype hcmd htimeout
                    htype=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" '.[$n][$ev][$i].type // "command"' "$file" 2>/dev/null)
                    hcmd=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" '.[$n][$ev][$i].command // ""' "$file" 2>/dev/null)
                    htimeout=$(jq -r --arg n "$hname" --arg ev "$ev" --argjson i "$idx" '.[$n][$ev][$i].timeout // "30"' "$file" 2>/dev/null)
                    
                    HOOKS+=("$hname|$ev|N/A|$htype|$hcmd|$enabled|$source|$htimeout")
                    if [[ "$enabled" == "true" ]]; then
                        local rtags
                        rtags="$(hook_risk_tags "$hcmd")"
                        if [[ "$rtags" == *"network-access"* || "$rtags" == *"destructive"* || "$rtags" == *"privileged"* ]]; then
                            add_finding "WARN" "Hooks" "High-risk lifecycle hook command ($ev): $hname" "cmd=$hcmd; tags=$rtags; source=$source"
                        else
                            add_finding "REVIEW" "Hooks" "Lifecycle hook command configured ($ev): $hname" "cmd=$hcmd; source=$source"
                        fi
                    fi
                done
            fi
        done

    done <<< "$hook_names"
}

collect_plugins() {
    local plugins_dir="$1" source="$2" config_json="${3:-}"
    [[ -d "$plugins_dir" ]] || return

    local pdir
    for pdir in "$plugins_dir"/*; do
        [[ -d "$pdir" ]] || continue
        local id="${pdir:t}"
        local manifest="$pdir/plugin.json"
        local pname="$id" pdisabled="false" enabled="true" features=()
        
        if [[ -f "$manifest" && "$HAS_JQ" == "true" ]]; then
            pname=$(jq -r '.name // "'"$id"'"' "$manifest" 2>/dev/null)
            pdisabled=$(jq -r 'if .disabled != null then .disabled | tostring else "false" end' "$manifest" 2>/dev/null)
        fi

        # Check config.json override
        if [[ -f "$config_json" && "$HAS_JQ" == "true" ]]; then
            local conf_override
            conf_override=$(jq -r --arg id "$id" '.plugins[$id].enabled // ""' "$config_json" 2>/dev/null)
            if [[ "$conf_override" == "true" ]]; then
                enabled="true"
            elif [[ "$conf_override" == "false" ]]; then
                enabled="false"
            elif [[ "$pdisabled" == "true" ]]; then
                enabled="false"
            fi
        elif [[ "$pdisabled" == "true" ]]; then
            enabled="false"
        fi

        [[ -d "$pdir/skills" ]] && features+=("skills")
        [[ -d "$pdir/rules" || -f "$pdir/rules/AGENTS.md" ]] && features+=("rules")
        [[ -f "$pdir/hooks.json" ]] && features+=("hooks")
        [[ -f "$pdir/mcp_config.json" ]] && features+=("mcp")

        local feats="${(j:,:)features}"
        PLUGINS+=("$id|$pname|$enabled|$source|$pdir|$feats")

        if [[ "$enabled" == "true" ]]; then
            add_finding "INFO" "Plugins" "Plugin '$pname' enabled" "features=${feats:-none}; source=$source"
            # Collect customizations inside enabled plugin
            [[ -f "$pdir/mcp_config.json" ]] && collect_mcp_file "$pdir/mcp_config.json" "plugin:$id"
            [[ -f "$pdir/hooks.json" ]] && collect_hooks_file "$pdir/hooks.json" "plugin:$id"
            [[ -d "$pdir/skills" ]] && collect_customizations "$pdir" "plugin:$id"
        else
            add_finding "INFO" "Plugins" "Plugin '$pname' disabled" "source=$source"
        fi
    done
}

collect_json_configs() {
    local base_dir="$1" source="$2"
    for cfile in "$base_dir/skills.json" "$base_dir/plugins.json"; do
        [[ -f "$cfile" ]] || continue
        add_sensitive_file "$(basename "$cfile")" "$cfile" "REVIEW"
        if [[ "$HAS_JQ" == "true" ]]; then
            local inherits_count entries_count
            inherits_count=$(jq -r '(.inherits // []) | length' "$cfile" 2>/dev/null)
            entries_count=$(jq -r '(.entries // []) | length' "$cfile" 2>/dev/null)
            if ((inherits_count > 0 || entries_count > 0)); then
                add_finding "INFO" "Customizations" "$(basename "$cfile") registered" "inherits=$inherits_count; entries=$entries_count; source=$source"
            fi
        fi
    done
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
    local config_dir="$1" source="$2" file parsed name desc skill_path scripts_dir script_count
    local skills_dir="$config_dir/skills"
    if [[ -d "$skills_dir" ]]; then
        for file in "$skills_dir"/**/SKILL.md; do
            [[ -f "$file" ]] || continue
            parsed=$(parse_skill_frontmatter "$file")
            name="${parsed%%|*}"
            local rest="${parsed#*|}"
            desc="${rest%%|*}"
            skill_path="${rest#*|}"
            SKILLS+=("$source|$name|$desc|$skill_path")
            
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
    for agents_md in "$config_dir/AGENTS.md" "$config_dir/GEMINI.md"; do
        if [[ -f "$agents_md" ]]; then
            add_finding "INFO" "Rules" "Rule file defined in $(basename "$agents_md")" "source=$source; path=$agents_md"
        fi
    done
    if [[ -d "$config_dir/rules" ]]; then
        for rfile in "$config_dir/rules"/*.md; do
            [[ -f "$rfile" ]] || continue
            add_finding "INFO" "Rules" "Rule file defined in $(basename "$rfile")" "source=$source; path=$rfile"
        done
    fi
}

collect_security_settings() {
    local settings="$1" scope="$2"
    [[ -f "$settings" ]] || return
    add_sensitive_file "$(basename "$settings") ($scope)" "$settings" "REVIEW"
    if [[ "$HAS_JQ" != "true" ]]; then
        return
    fi

    # 1. Tool execution policy / Auto execution
    local tool_policy auto_policy
    tool_policy=$(jq -r '.toolExecutionPolicy // .general.toolExecutionPolicy // ""' "$settings" 2>/dev/null)
    auto_policy=$(jq -r '.autoExecutionPolicy // ""' "$settings" 2>/dev/null)
    local eff_policy="${tool_policy:-$auto_policy}"
    if [[ -n "$eff_policy" ]]; then
        local rlevel="INFO"
        [[ "$eff_policy" == "always-proceed" ]] && rlevel="WARN"
        SECURITY_SETTINGS+=("$scope|toolExecutionPolicy|$eff_policy|$rlevel")
        if [[ "$eff_policy" == "always-proceed" ]]; then
            add_finding "WARN" "Security Settings" "Unrestricted tool execution policy enabled (always-proceed)" "scope=$scope; setting=toolExecutionPolicy"
        else
            add_finding "INFO" "Security Settings" "Tool execution policy: $eff_policy" "scope=$scope"
        fi
    fi

    # 2. Terminal Sandbox mode
    local sandbox_enabled sandbox_net
    sandbox_enabled=$(jq -r 'if .sandbox.enabled != null then .sandbox.enabled | tostring elif .terminalSandbox != null then .terminalSandbox | tostring else "" end' "$settings" 2>/dev/null)
    sandbox_net=$(jq -r 'if .sandbox.network != null then .sandbox.network | tostring elif .networkIsolation != null then .networkIsolation | tostring else "" end' "$settings" 2>/dev/null)
    if [[ -n "$sandbox_enabled" ]]; then
        local rlevel="INFO"
        [[ "$sandbox_enabled" == "false" ]] && rlevel="WARN"
        SECURITY_SETTINGS+=("$scope|sandbox.enabled|$sandbox_enabled|$rlevel")
        if [[ "$sandbox_enabled" == "false" ]]; then
            add_finding "WARN" "Security Settings" "Terminal command sandboxing is disabled" "scope=$scope"
        fi
    fi
    if [[ -n "$sandbox_net" ]]; then
        local rlevel="INFO"
        [[ "$sandbox_net" == "false" || "$sandbox_net" == "allow" ]] && rlevel="REVIEW"
        SECURITY_SETTINGS+=("$scope|sandbox.network|$sandbox_net|$rlevel")
        if [[ "$sandbox_net" == "false" || "$sandbox_net" == "allow" ]]; then
            add_finding "REVIEW" "Security Settings" "Terminal sandbox network isolation is disabled/allowed" "scope=$scope"
        fi
    fi

    # 3. Non-workspace file access policy
    local file_access
    file_access=$(jq -r '.nonWorkspaceFileAccess // .fileAccessPolicy // ""' "$settings" 2>/dev/null)
    if [[ -n "$file_access" ]]; then
        local rlevel="INFO"
        [[ "$file_access" == "allow" ]] && rlevel="WARN"
        SECURITY_SETTINGS+=("$scope|nonWorkspaceFileAccess|$file_access|$rlevel")
        if [[ "$file_access" == "allow" ]]; then
            add_finding "WARN" "Security Settings" "Non-workspace file access policy set to 'allow'" "scope=$scope"
        elif [[ "$file_access" == "deny" ]]; then
            add_finding "INFO" "Security Settings" "Non-workspace file access policy set to 'deny'" "scope=$scope"
        fi
    fi

    # 4. Internet access policy
    local net_access
    net_access=$(jq -r '.internetAccessPolicy // .networkAccess // ""' "$settings" 2>/dev/null)
    if [[ -n "$net_access" ]]; then
        local rlevel="INFO"
        [[ "$net_access" == "allow" ]] && rlevel="REVIEW"
        SECURITY_SETTINGS+=("$scope|internetAccessPolicy|$net_access|$rlevel")
        if [[ "$net_access" == "allow" ]]; then
            add_finding "REVIEW" "Security Settings" "Internet access policy set to unrestricted 'allow'" "scope=$scope"
        fi
    fi

    # 5. Browser domain policy / Allowlist
    local browser_allow
    browser_allow=$(jq -r '(.browserAllowlist // .browserDomainPolicy // []) | join(",")' "$settings" 2>/dev/null)
    if [[ -n "$browser_allow" ]]; then
        local rlevel="INFO"
        [[ "$browser_allow" == "*" ]] && rlevel="REVIEW"
        SECURITY_SETTINGS+=("$scope|browserAllowlist|$browser_allow|$rlevel")
        if [[ "$browser_allow" == "*" ]]; then
            add_finding "REVIEW" "Security Settings" "Browser navigation allows all domains (*)" "scope=$scope"
        fi
    fi

    # 6. Command allowlist / denylist
    local cmd_allow cmd_deny
    cmd_allow=$(jq -r '(.commandAllowlist // []) | join(",")' "$settings" 2>/dev/null)
    cmd_deny=$(jq -r '(.commandDenylist // []) | join(",")' "$settings" 2>/dev/null)
    if [[ -n "$cmd_allow" ]]; then
        SECURITY_SETTINGS+=("$scope|commandAllowlist|$cmd_allow|INFO")
        for hint in ${(z)DANGEROUS_MCP_HINTS}; do
            if [[ "$cmd_allow" == *"$hint"* ]]; then
                add_finding "WARN" "Security Settings" "Command allowlist contains risky tool: $hint" "scope=$scope; allowlist=$cmd_allow"
                break
            fi
        done
    fi
    if [[ -n "$cmd_deny" ]]; then
        SECURITY_SETTINGS+=("$scope|commandDenylist|$cmd_deny|INFO")
    fi

    # 7. Artifact review mode
    local artifact_review
    artifact_review=$(jq -r '.artifactReviewMode // ""' "$settings" 2>/dev/null)
    if [[ -n "$artifact_review" ]]; then
        local rlevel="INFO"
        [[ "$artifact_review" == "always-proceed" ]] && rlevel="REVIEW"
        SECURITY_SETTINGS+=("$scope|artifactReviewMode|$artifact_review|$rlevel")
        if [[ "$artifact_review" == "always-proceed" ]]; then
            add_finding "REVIEW" "Security Settings" "Artifact review mode is set to 'always-proceed'" "scope=$scope"
        fi
    fi
}

collect_main_config() {
    local settings="$ANTIGRAVITY_DIR/settings.json"
    if [[ -f "$settings" ]]; then
        collect_security_settings "$settings" "global"
        if [[ "$HAS_JQ" == "true" ]]; then
            local model theme retention_enabled max_age
            model=$(jq -r '.model.name // .model // ""' "$settings" 2>/dev/null)
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

    # Antigravity 2.0 app settings
    local app_settings="$ANTIGRAVITY_DIR/antigravity/settings.json"
    [[ -f "$app_settings" ]] && collect_security_settings "$app_settings" "app"

    # CLI settings
    local cli_settings="$ANTIGRAVITY_DIR/antigravity-cli/settings.json"
    if [[ -f "$cli_settings" ]]; then
        collect_security_settings "$cli_settings" "cli"
        if [[ "$HAS_JQ" == "true" ]]; then
            local cli_model
            cli_model=$(jq -r '.model // ""' "$cli_settings" 2>/dev/null)
            [[ -n "$cli_model" ]] && add_finding "INFO" "Config" "CLI model: $cli_model"
        fi
    fi
}

collect_projects() {
    local projects="$ANTIGRAVITY_DIR/projects.json"
    if [[ -f "$projects" ]]; then
        add_sensitive_file "projects.json" "$projects" "REVIEW"
        if [[ "$HAS_JQ" == "true" ]]; then
            local keys proj_path name has_agents
            keys=$(jq -r '.projects | keys[]' "$projects" 2>/dev/null) || return
            while read -r proj_path; do
                [[ -z "$proj_path" ]] && continue
                name=$(jq -r --arg p "$proj_path" '.projects[$p]' "$projects" 2>/dev/null)
                has_agents="false"
                if [[ -d "$proj_path" ]]; then
                    local agents_dir="$proj_path/.agents"
                    [[ ! -d "$agents_dir" && -d "$proj_path/.agent" ]] && agents_dir="$proj_path/.agent"
                    if [[ -d "$agents_dir" ]]; then
                        has_agents="true"
                        collect_customizations "$agents_dir" "workspace:$name"
                        [[ -f "$agents_dir/mcp_config.json" ]] && collect_mcp_file "$agents_dir/mcp_config.json" "workspace:$name"
                        [[ -f "$agents_dir/hooks.json" ]] && collect_hooks_file "$agents_dir/hooks.json" "workspace:$name"
                        [[ -d "$agents_dir/plugins" ]] && collect_plugins "$agents_dir/plugins" "workspace:$name" "$agents_dir/config.json"
                        collect_json_configs "$agents_dir" "workspace:$name"
                    fi
                    # Check project-level settings
                    for pset in "$proj_path/.gemini/settings.json" "$proj_path/.agents/settings.json"; do
                        [[ -f "$pset" ]] && collect_security_settings "$pset" "project:$name"
                    done
                fi
                PROJECTS+=("$proj_path|$name|$has_agents")
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
            local keys folder level summary
            keys=$(jq -r 'keys[]' "$trusted" 2>/dev/null) || return
            while read -r folder; do
                [[ -z "$folder" ]] && continue
                level=$(jq -r --arg p "$folder" '.[$p]' "$trusted" 2>/dev/null)
                summary=$(get_file_broad_summary "$folder")
                # Remove broad= suffix
                summary="${summary% broad=*}"
                TRUSTED_FOLDERS+=("$folder|$level|$summary")
                add_finding "WARN" "Trusted Folders" "Trusted folder grants Antigravity broader workspace autonomy" "path=$folder; trust=$level"
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
    add_retention_dir "antigravity-brain" "$ANTIGRAVITY_DIR/antigravity/brain" 524288000 # 500MB
    add_retention_dir "antigravity-cli" "$ANTIGRAVITY_DIR/antigravity-cli" 209715200 # 200MB
}

collect_runtime() {
    local count
    count=$(pgrep -f 'antigravity|gemini' 2>/dev/null | wc -l | tr -d ' ')
    if ((count > 0)); then
        add_finding "INFO" "Runtime" "Active antigravity/gemini process(es) detected: $count"
    fi
}

# Pick the nth (1-based) |-delimited field out of a packed inventory row.
# Indexing an array here would depend on KSH_ARRAYS, which this script sets, so
# strip prefixes instead: that behaves the same whichever way arrays are indexed.
json_split_field() {
    local s="$1" field="$2"
    local rest="$s"
    local i
    for ((i=1; i<field; i++)); do
        rest="${rest#*|}"
    done
    printf '%s' "${rest%%|*}"
}

render_json() {
    local findings="[" idx=0 i
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        ((idx > 0)) && findings+=","
        findings+="{\"severity\":$(jstr "${FINDING_SEV[$i]}"),\"section\":$(jstr "${FINDING_SECT[$i]}"),\"message\":$(jstr_out "${FINDING_MSG[$i]}"),\"detail\":$(jstr_out "${FINDING_DET[$i]}")}"
        ((idx++))
    done
    findings+="]"

    local mcp="[" idx=0
    for name in "${MCP_NAMES[@]}"; do
        ((idx > 0)) && mcp+=","
        mcp+="{\"name\":$(jstr_out "$name"),\"type\":$(jstr "${MCP_TYPE[$name]:-stdio}"),\"command_or_url\":$(jstr_out "${MCP_CMDS[$name]:-}"),\"args\":$(jstr_out "${MCP_ARGS[$name]:-}"),\"env_keys\":$(jstr "${MCP_ENVKEYS[$name]:-}"),\"source\":$(jstr "${MCP_SOURCE[$name]:-}")}"
        ((idx++))
    done
    mcp+="]"

    local hooks="[" idx=0
    for row in "${HOOKS[@]}"; do
        ((idx > 0)) && hooks+=","
        hooks+="{\"name\":$(jstr_out "$(json_split_field "$row" 1)"),\"event\":$(jstr "$(json_split_field "$row" 2)"),\"matcher\":$(jstr "$(json_split_field "$row" 3)"),\"type\":$(jstr "$(json_split_field "$row" 4)"),\"command\":$(jstr_out "$(json_split_field "$row" 5)"),\"enabled\":$(jstr "$(json_split_field "$row" 6)"),\"source\":$(jstr "$(json_split_field "$row" 7)"),\"timeout\":$(jstr "$(json_split_field "$row" 8)")}"
        ((idx++))
    done
    hooks+="]"

    local plugins="[" idx=0
    for row in "${PLUGINS[@]}"; do
        ((idx > 0)) && plugins+=","
        plugins+="{\"id\":$(jstr_out "$(json_split_field "$row" 1)"),\"name\":$(jstr_out "$(json_split_field "$row" 2)"),\"enabled\":$(jstr "$(json_split_field "$row" 3)"),\"source\":$(jstr "$(json_split_field "$row" 4)"),\"path\":$(jstr_out "$(json_split_field "$row" 5)"),\"features\":$(jstr "$(json_split_field "$row" 6)")}"
        ((idx++))
    done
    plugins+="]"

    local sec_settings="[" idx=0
    for row in "${SECURITY_SETTINGS[@]}"; do
        ((idx > 0)) && sec_settings+=","
        sec_settings+="{\"scope\":$(jstr "$(json_split_field "$row" 1)"),\"key\":$(jstr "$(json_split_field "$row" 2)"),\"value\":$(jstr_out "$(json_split_field "$row" 3)"),\"risk_level\":$(jstr "$(json_split_field "$row" 4)")}"
        ((idx++))
    done
    sec_settings+="]"

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

    printf '{"timestamp":%s,"hostname":%s,"username":%s,"antigravity_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d},"findings":%s,"mcp_servers":%s,"hooks":%s,"plugins":%s,"security_settings":%s,"trusted_folders":%s,"projects":%s,"skills":%s,"sensitive_files":%s,"retention":%s}' \
        "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$ANTIGRAVITY_DIR")" \
        "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$findings" "$mcp" "$hooks" "$plugins" "$sec_settings" "$tf" \
        "$projects" "$skills" "$sens_files" "$retention"
}

render_diff_json() {
    local baseline="$1"
    if [[ "$HAS_JQ" != "true" ]]; then
        print -r -- "Error: --diff requires jq" >&2
        return 1
    fi
    if [[ ! -r "$baseline" ]]; then
        print -r -- "Error: cannot read baseline: $baseline" >&2
        return 1
    fi
    local current_json
    current_json="$(render_json)"
    jq --argjson current "$current_json" '
      def arr(x): if x == null then [] elif (x|type) == "array" then x else [x] end;
      def keys_for($doc; $path; $field):
        [arr($doc)[] | getpath($path)? // [] | .[]? | .[$field] // empty] | unique;
      def skill_keys($doc):
        [arr($doc)[] | .skills[]? | ((.source // "") + ":" + (.name // ""))] | unique;
      def hook_keys($doc):
        [arr($doc)[] | .hooks[]? | ((.event // "") + ":" + (.name // "") + ":" + (.command // ""))] | unique;
      def sec_keys($doc):
        [arr($doc)[] | .security_settings[]? | ((.scope // "") + ":" + (.key // "") + "=" + (.value // ""))] | unique;
      def section($name; $old; $new):
        {
          section: $name,
          added: (($new - $old) | sort),
          removed: (($old - $new) | sort)
        };
      . as $base
      | [
          section("mcp_servers"; keys_for($base; ["mcp_servers"]; "name"); keys_for($current; ["mcp_servers"]; "name")),
          section("hooks"; hook_keys($base); hook_keys($current)),
          section("plugins"; keys_for($base; ["plugins"]; "id"); keys_for($current; ["plugins"]; "id")),
          section("security_settings"; sec_keys($base); sec_keys($current)),
          section("trusted_folders"; keys_for($base; ["trusted_folders"]; "path"); keys_for($current; ["trusted_folders"]; "path")),
          section("projects"; keys_for($base; ["projects"]; "path"); keys_for($current; ["projects"]; "path")),
          section("skills"; skill_keys($base); skill_keys($current))
        ]
      | {changed: map(select((.added|length) > 0 or (.removed|length) > 0))}
      | . + {has_changes: ((.changed | length) > 0)}
    ' "$baseline"
}

render_diff() {
    local diff_json
    diff_json="$(render_diff_json "$1")" || return 1
    if [[ "$OPT_DIFF_JSON" == "true" ]]; then
        print -r -- "$diff_json"
        return 0
    fi
    jq -r '
      .changed
      | if length == 0 then
          "No baseline differences detected."
        else
          .[] | (
            "## " + .section,
            (if (.added|length) > 0 then "Added:\n" + (.added | map("  + " + .) | join("\n")) else empty end),
            (if (.removed|length) > 0 then "Removed:\n" + (.removed | map("  - " + .) | join("\n")) else empty end)
          )
        end
    ' <<< "$diff_json"
}

html_rows_findings() {
    local i
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
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
EOF

    # MCP Servers Table
    if ((${#MCP_NAMES[@]} > 0)); then
        cat <<EOF
<h2>MCP Servers</h2>
<table>
<thead><tr><th>Name</th><th>Type</th><th>Command / URL</th><th>Env Keys</th><th>Source</th></tr></thead>
<tbody>
EOF
        for name in "${MCP_NAMES[@]}"; do
            printf '<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>\n' \
                "$(html_out "$name")" "$(html_escape "${MCP_TYPE[$name]:-stdio}")" "$(html_out "${MCP_CMDS[$name]:-}")" "$(html_escape "${MCP_ENVKEYS[$name]:-}")" "$(html_escape "${MCP_SOURCE[$name]:-}")"
        done
        printf '</tbody></table>\n'
    fi

    # Hooks Table
    if ((${#HOOKS[@]} > 0)); then
        cat <<EOF
<h2>Lifecycle Hooks</h2>
<table>
<thead><tr><th>Name</th><th>Event</th><th>Matcher</th><th>Command</th><th>Enabled</th><th>Source</th></tr></thead>
<tbody>
EOF
        for row in "${HOOKS[@]}"; do
            printf '<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>\n' \
                "$(html_out "$(json_split_field "$row" 1)")" "$(html_escape "$(json_split_field "$row" 2)")" "$(html_escape "$(json_split_field "$row" 3)")" \
                "$(html_out "$(json_split_field "$row" 5)")" "$(html_escape "$(json_split_field "$row" 6)")" "$(html_escape "$(json_split_field "$row" 7)")"
        done
        printf '</tbody></table>\n'
    fi

    # Plugins Table
    if ((${#PLUGINS[@]} > 0)); then
        cat <<EOF
<h2>Plugins</h2>
<table>
<thead><tr><th>ID</th><th>Name</th><th>Enabled</th><th>Features</th><th>Source</th></tr></thead>
<tbody>
EOF
        for row in "${PLUGINS[@]}"; do
            printf '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n' \
                "$(html_out "$(json_split_field "$row" 1)")" "$(html_out "$(json_split_field "$row" 2)")" "$(html_escape "$(json_split_field "$row" 3)")" \
                "$(html_escape "$(json_split_field "$row" 6)")" "$(html_escape "$(json_split_field "$row" 4)")"
        done
        printf '</tbody></table>\n'
    fi

    # Security Settings Table
    if ((${#SECURITY_SETTINGS[@]} > 0)); then
        cat <<EOF
<h2>Security Settings</h2>
<table>
<thead><tr><th>Scope</th><th>Setting</th><th>Value</th><th>Risk</th></tr></thead>
<tbody>
EOF
        for row in "${SECURITY_SETTINGS[@]}"; do
            printf '<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><span class="badge %s">%s</span></td></tr>\n' \
                "$(html_escape "$(json_split_field "$row" 1)")" "$(html_escape "$(json_split_field "$row" 2)")" "$(html_out "$(json_split_field "$row" 3)")" \
                "$(html_escape "${(L)$(json_split_field "$row" 4)}")" "$(html_escape "$(json_split_field "$row" 4)")"
        done
        printf '</tbody></table>\n'
    fi

    cat <<EOF
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
table{width:100%;border-collapse:collapse;border:1px solid #30363d;margin-bottom:20px}
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
    local i shown
    if [[ "$OPT_SUMMARY" == "true" ]]; then
        printf '%s  WARN=%d REVIEW=%d INFO=%d  %s\n' "$(display_text "$AUDIT_USER")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$(display_text "$ANTIGRAVITY_DIR")"
        shown=0
        for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
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
        for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
            [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
            printf '  [%s] %-16s %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
            [[ -n "${FINDING_DET[$i]}" ]] && printf '       %s\n' "$(display_text "${FINDING_DET[$i]}")"
        done
        printf '\n'
    fi

    # MCP Servers
    print -r -- 'MCP Servers'
    if ((${#MCP_NAMES[@]} == 0)); then print -r -- '  none'; else
        for name in "${MCP_NAMES[@]}"; do
            printf '  %-22s type=%s cmd=%s source=%s\n' "$(display_text "$name")" "${MCP_TYPE[$name]:-stdio}" "$(display_text "${MCP_CMDS[$name]:-}")" "${MCP_SOURCE[$name]:-}"
        done
    fi
    printf '\n'

    # Hooks
    print -r -- 'Lifecycle Hooks'
    if ((${#HOOKS[@]} == 0)); then print -r -- '  none'; else
        for row in "${HOOKS[@]}"; do
            printf '  %-22s event=%s cmd=%s enabled=%s source=%s\n' "$(display_text "$(json_split_field "$row" 1)")" "$(json_split_field "$row" 2)" "$(display_text "$(json_split_field "$row" 5)")" "$(json_split_field "$row" 6)" "$(json_split_field "$row" 7)"
        done
    fi
    printf '\n'

    # Plugins
    print -r -- 'Plugins'
    if ((${#PLUGINS[@]} == 0)); then print -r -- '  none'; else
        for row in "${PLUGINS[@]}"; do
            printf '  %-22s enabled=%s features=%s source=%s\n' "$(display_text "$(json_split_field "$row" 1)")" "$(json_split_field "$row" 3)" "$(json_split_field "$row" 6)" "$(json_split_field "$row" 4)"
        done
    fi
    printf '\n'

    # Security Settings
    print -r -- 'Security Settings'
    if ((${#SECURITY_SETTINGS[@]} == 0)); then print -r -- '  none'; else
        for row in "${SECURITY_SETTINGS[@]}"; do
            printf '  %-22s key=%s value=%s risk=%s\n' "$(json_split_field "$row" 1)" "$(json_split_field "$row" 2)" "$(display_text "$(json_split_field "$row" 3)")" "$(json_split_field "$row" 4)"
        done
    fi
    printf '\n'

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
    reset_state
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
    if [[ -d "$global_config" ]]; then
        collect_customizations "$global_config" "global"
        [[ -f "$global_config/mcp_config.json" ]] && collect_mcp_file "$global_config/mcp_config.json" "global"
        [[ -f "$global_config/hooks.json" ]] && collect_hooks_file "$global_config/hooks.json" "global"
        [[ -d "$global_config/plugins" ]] && collect_plugins "$global_config/plugins" "global" "$global_config/config.json"
        collect_json_configs "$global_config" "global"
    fi

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

local first_user=("${(@k)targets}")
first_user="${first_user[1]}"
local first_home="${targets[$first_user]}"

run_user_audit "$first_user" "$first_home"

# Generate report or diff
local content=""
if [[ -n "$OPT_DIFF" ]]; then
    render_diff "$OPT_DIFF"
    exit $?
elif [[ "$OPT_JSON" == "true" ]]; then
    content=$(render_json)
elif [[ -n "$OPT_HTML" ]]; then
    content=$(render_html)
else
    content=$(write_terminal_report)
fi

# Output logic
if [[ -n "$OPT_HTML" ]]; then
    out_file="$OPT_HTML"
    if [[ "$out_file" == "AUTO" ]]; then
        out_file="antigravity_audit_$(date '+%Y%m%d_%H%M%S').html"
    fi
    printf '%s' "$content" > "$out_file"
    printf 'HTML report written: %s\n' "$out_file"
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
