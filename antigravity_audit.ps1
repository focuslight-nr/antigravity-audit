# ANTIGRAVITY-AUDIT - Antigravity local security audit tool (Windows/PowerShell)
# Read-only audit for ~/.gemini configuration, MCP servers, hooks, plugins, projects, trusted folders, security policies, and sensitive files.
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'
$script:Version = '0.2.0'
$script:AntigravityDirName = '.gemini'
$script:DangerousMcpHints = @('bash', 'sh', 'zsh', 'python', 'python3', 'node', 'ruby', 'perl', 'osascript', 'sqlite3', 'psql', 'mysql', 'curl', 'wget', 'nc', 'ncat', 'ssh', 'scp')
$script:SensitiveNamePattern = '(?i)(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)'

$script:Options = @{
    Json = $false
    Diff = $null
    DiffJson = $false
    Html = $null
    Summary = $false
    Output = $null
    FailOn = $null
    RedactPaths = $false
    User = $null
    AllUsers = $false
    AntigravityDir = $null
    Quiet = $false
}

function Show-Usage {
    @"
ANTIGRAVITY-AUDIT v$($script:Version) - Antigravity local security audit
Usage: .\antigravity_audit.ps1 [--html [FILE]] [--json] [--summary] [--output FILE]
       [--diff BASELINE.json] [--diff-json] [--fail-on warn|review]
       [--redact-paths] [--user USER] [--all-users]
       [--antigravity-dir DIR] [-q|--quiet] [--version] [-h|--help]
"@
}

function Exit-ArgumentError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    [Console]::Error.WriteLine((Show-Usage))
    exit 1
}

# Parse Command Line Arguments
for ($i = 0; $i -lt $CliArgs.Count; $i++) {
    $arg = $CliArgs[$i]
    switch ($arg) {
        '--json' { $script:Options.Json = $true }
        '--diff-json' { $script:Options.DiffJson = $true }
        '--summary' { $script:Options.Summary = $true }
        '--redact-paths' { $script:Options.RedactPaths = $true }
        '--all-users' { $script:Options.AllUsers = $true }
        '--quiet' { $script:Options.Quiet = $true }
        '-q' { $script:Options.Quiet = $true }
        '--version' { Write-Output "ANTIGRAVITY-AUDIT v$($script:Version)"; exit 0 }
        '--help' { Write-Output (Show-Usage); exit 0 }
        '-h' { Write-Output (Show-Usage); exit 0 }
        '--html' {
            if (($i + 1) -lt $CliArgs.Count -and -not $CliArgs[$i + 1].StartsWith('-')) {
                $i++
                $script:Options.Html = $CliArgs[$i]
            } else {
                $script:Options.Html = 'AUTO'
            }
        }
        { $_ -in @('--output', '--fail-on', '--user', '--antigravity-dir', '--diff') } {
            if (($i + 1) -ge $CliArgs.Count) { Exit-ArgumentError "Missing value for $arg" }
            $i++
            $value = $CliArgs[$i]
            switch ($arg) {
                '--output' { $script:Options.Output = $value }
                '--diff' { $script:Options.Diff = $value }
                '--fail-on' { $script:Options.FailOn = $value.ToLowerInvariant() }
                '--user' { $script:Options.User = $value }
                '--antigravity-dir' { $script:Options.AntigravityDir = $value }
            }
        }
        default { Exit-ArgumentError "Unknown option: $arg" }
    }
}

if ($script:Options.Diff -and $script:Options.Html) {
    Exit-ArgumentError '--diff and --html are mutually exclusive'
}
if ($script:Options.Diff -and $script:Options.Json -and -not $script:Options.DiffJson) {
    Exit-ArgumentError '--diff and --json are mutually exclusive; use --diff-json for JSON diff output'
}
if ($script:Options.DiffJson -and -not $script:Options.Diff) {
    Exit-ArgumentError '--diff-json requires --diff BASELINE.json'
}
if ($script:Options.Json -and $script:Options.Html) {
    Exit-ArgumentError '--json and --html are mutually exclusive'
}
if ($script:Options.AllUsers -and $script:Options.User) {
    Exit-ArgumentError '--user and --all-users are mutually exclusive'
}
if ($script:Options.AllUsers -and $script:Options.AntigravityDir) {
    Exit-ArgumentError '--antigravity-dir and --all-users are mutually exclusive'
}
if ($script:Options.AntigravityDir -and -not (Test-Path -LiteralPath $script:Options.AntigravityDir -PathType Container)) {
    Exit-ArgumentError "--antigravity-dir does not exist: $($script:Options.AntigravityDir)"
}
if (-not $script:Options.Html -and $script:Options.Output -and
    [IO.Path]::GetExtension($script:Options.Output) -ieq '.html') {
    Exit-ArgumentError '--output .html requires --html'
}
if ($script:Options.FailOn -and $script:Options.FailOn -notin @('warn', 'review')) {
    Exit-ArgumentError "--fail-on must be 'warn' or 'review'"
}

function New-AuditState([string]$UserName, [string]$HomeDir, [string]$AntigravityDir) {
    @{
        User = $UserName
        Home = $HomeDir
        AntigravityDir = $AntigravityDir
        Timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        Hostname = [Environment]::MachineName
        Findings = [Collections.Generic.List[object]]::new()
        McpServers = [Collections.Generic.List[object]]::new()
        Hooks = [Collections.Generic.List[object]]::new()
        Plugins = [Collections.Generic.List[object]]::new()
        SecuritySettings = [Collections.Generic.List[object]]::new()
        TrustedFolders = [Collections.Generic.List[object]]::new()
        Projects = [Collections.Generic.List[object]]::new()
        Skills = [Collections.Generic.List[object]]::new()
        SensitiveFiles = [Collections.Generic.List[object]]::new()
        Retention = [Collections.Generic.List[object]]::new()
    }
}

function Add-Finding {
    param($State, [string]$Severity, [string]$Section, [string]$Message, [string]$Detail = '')
    $State.Findings.Add([pscustomobject]@{
        severity = $Severity
        section = $Section
        message = $Message
        detail = $Detail
    })
}

function Get-Summary($State) {
    [ordered]@{
        warn = @($State.Findings | Where-Object severity -eq 'WARN').Count
        review = @($State.Findings | Where-Object severity -eq 'REVIEW').Count
        info = @($State.Findings | Where-Object severity -eq 'INFO').Count
    }
}

function Mask-Email([string]$Email) {
    if (-not $Email) { return '' }
    if ($script:Options.RedactPaths) { return '[REDACTED]' }
    if ($Email -like '*@*') {
        $parts = $Email -split '@', 2
        $name = $parts[0]
        $domain = $parts[1]
        $maskedName = if ($name.Length -gt 2) {
            $name.Substring(0, 2) + ('*' * ($name.Length - 2))
        } else {
            $name + '**'
        }
        return "$maskedName@$domain"
    }
    return $Email
}

function Get-DisplayText($State, [AllowNull()][object]$Value) {
    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($script:Options.RedactPaths) {
        if ($State.Home) { $text = $text.Replace($State.Home, '~') }
        if ($State.User) {
            $text = $text -replace "(?i)(C:\\Users\\)$([regex]::Escape($State.User))", '$1[USER]'
            $text = $text -replace "(?i)(\/Users\/)$([regex]::Escape($State.User))", '$1[USER]'
        }
    }
    $text
}

function Read-JsonFile([string]$Path) {
    try {
        Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $null
    }
}

function Get-Property($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $null
}

function Get-ObjectEntries($Object) {
    if ($null -eq $Object) { return @() }
    @($Object.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Value = $_.Value }
    })
}

function Join-Values($Value) {
    if ($null -eq $Value) { return '' }
    @($Value) -join ', '
}

function Get-FileAclSummary([string]$Path) {
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = $acl.Owner
        $broad = @($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -match '(?i)(Everyone|BUILTIN\\Users|Authenticated Users)' -and
            ($_.FileSystemRights.ToString() -match '(?i)(Read|Write|Modify|FullControl)')
        })
        [pscustomobject]@{
            Summary = "owner=$owner; broad_access=$($broad.Count)"
            IsBroad = $broad.Count -gt 0
        }
    } catch {
        [pscustomobject]@{ Summary = 'ACL unavailable'; IsBroad = $false }
    }
}

function Add-SensitiveFile($State, [string]$Name, [string]$Path, [ValidateSet('', 'WARN', 'REVIEW')][string]$BroadSeverity = '') {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $acl = Get-FileAclSummary $Path
    $State.SensitiveFiles.Add([pscustomobject]@{
        name = $Name
        mode = $acl.Summary
        path = $Path
    })
    if ($BroadSeverity -and $acl.IsBroad) {
        Add-Finding $State $BroadSeverity 'Sensitive Files' "$Name grants access to broad Windows principals" "$($acl.Summary); path=$Path"
    }
}

function Parse-SkillFrontmatter([string]$Path) {
    $fallback = Split-Path (Split-Path $Path -Parent) -Leaf
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{ name = $fallback; description = '' } }
    try {
        $lines = Get-Content -LiteralPath $Path -TotalCount 20 -ErrorAction SilentlyContinue
        if (-not $lines -or $lines[0] -notlike '---*') { return [pscustomobject]@{ name = $fallback; description = '' } }
        $name = ''
        $desc = ''
        $inDesc = $false
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -eq '---' -and ($name -or $desc)) { break }
            if ($trimmed -like 'name:*') {
                $name = $trimmed.Substring(5).Trim().Trim('"').Trim("'")
                $inDesc = $false
            } elseif ($trimmed -like 'description:*') {
                $desc = $trimmed.Substring(12).Trim().Trim('"').Trim("'")
                if ($desc -in @('>', '|')) { $desc = '' }
                $inDesc = $true
            } elseif ($inDesc -and $line.StartsWith('  ')) {
                $desc = (($desc, $line.Trim()) | Where-Object { $_ }) -join ' '
            } elseif ($trimmed -ne '---') {
                $inDesc = $false
            }
        }
        if (-not $name) { $name = $fallback }
        return [pscustomobject]@{ name = $name; description = $desc }
    } catch {
        return [pscustomobject]@{ name = $fallback; description = '' }
    }
}

function Collect-McpFile($State, [string]$Path, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Add-SensitiveFile $State (Split-Path $Path -Leaf) $Path 'REVIEW'
    $json = Read-JsonFile $Path
    if ($null -eq $json) {
        Add-Finding $State 'INFO' 'MCP Servers' "MCP config found at $Path (unable to parse JSON)" "source=$Source"
        return
    }
    $serversObj = Get-Property $json 'mcpServers'
    foreach ($server in (Get-ObjectEntries $serversObj)) {
        $name = $server.Name
        $cfg = $server.Value
        $cmd = [string](Get-Property $cfg 'command')
        $args = (Get-Property $cfg 'args')
        $argsStr = if ($args) { ($args | ForEach-Object { [string]$_ }) -join ' ' } else { '' }
        $url = [string](Get-Property $cfg 'serverUrl')
        $envObj = Get-Property $cfg 'env'
        $envKeys = if ($envObj) { (Get-ObjectEntries $envObj | ForEach-Object { $_.Name }) -join ',' } else { '' }

        if ($url) {
            $State.McpServers.Add([pscustomobject]@{
                name = $name
                type = 'sse'
                command_or_url = $url
                args = ''
                env_keys = ''
                source = $Source
            })
            if ($url -like 'http://*') {
                Add-Finding $State 'WARN' 'MCP Servers' "Unencrypted SSE MCP server: $name" "url=$url; source=$Source"
            } else {
                Add-Finding $State 'REVIEW' 'MCP Servers' "Remote SSE MCP server configured: $name" "url=$url; source=$Source"
            }
        } else {
            $State.McpServers.Add([pscustomobject]@{
                name = $name
                type = 'stdio'
                command_or_url = $cmd
                args = $argsStr
                env_keys = $envKeys
                source = $Source
            })
            $cmdLeaf = Split-Path $cmd -Leaf
            $isDangerous = $false
            foreach ($hint in $script:DangerousMcpHints) {
                if ($cmdLeaf -eq $hint -or $cmd -like "*\$hint" -or $cmd -like "*/$hint") {
                    $isDangerous = $true
                    break
                }
            }
            if ($isDangerous) {
                Add-Finding $State 'WARN' 'MCP Servers' "MCP server executes broad command runner: $name" "cmd=$cmd $argsStr; source=$Source"
            } else {
                Add-Finding $State 'REVIEW' 'MCP Servers' "Local MCP server configured: $name" "cmd=$cmd $argsStr; source=$Source"
            }
            if ($envKeys -match $script:SensitiveNamePattern) {
                Add-Finding $State 'REVIEW' 'MCP Servers' "MCP server has sensitive environment variables: $name" "keys=$envKeys; source=$Source"
            }
        }
    }
}

function Collect-HooksFile($State, [string]$Path, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Add-SensitiveFile $State (Split-Path $Path -Leaf) $Path 'REVIEW'
    $json = Read-JsonFile $Path
    if ($null -eq $json) {
        Add-Finding $State 'INFO' 'Hooks' "Hooks config found at $Path (unable to parse JSON)" "source=$Source"
        return
    }

    foreach ($hookEntry in (Get-ObjectEntries $json)) {
        $hname = $hookEntry.Name
        $hcfg = $hookEntry.Value
        $enabledVal = Get-Property $hcfg 'enabled'
        $enabled = if ($null -ne $enabledVal) { $enabledVal.ToString().ToLowerInvariant() } else { 'true' }

        # Grouped events (PreToolUse, PostToolUse)
        foreach ($ev in @('PreToolUse', 'PostToolUse')) {
            $evList = Get-Property $hcfg $ev
            if ($evList) {
                foreach ($grp in @($evList)) {
                    $matcher = [string](Get-Property $grp 'matcher')
                    if (-not $matcher) { $matcher = '*' }
                    $innerHooks = Get-Property $grp 'hooks'
                    if ($innerHooks) {
                        foreach ($h in @($innerHooks)) {
                            $htype = [string](Get-Property $h 'type')
                            if (-not $htype) { $htype = 'command' }
                            $hcmd = [string](Get-Property $h 'command')
                            $htimeout = [string](Get-Property $h 'timeout')
                            if (-not $htimeout) { $htimeout = '30' }

                            $State.Hooks.Add([pscustomobject]@{
                                name = $hname
                                event = $ev
                                matcher = $matcher
                                type = $htype
                                command = $hcmd
                                enabled = $enabled
                                source = $Source
                                timeout = $htimeout
                            })
                            if ($enabled -eq 'true') {
                                if ($hcmd -match '(?i)(curl|wget|nc|fetch|rm\s+-rf|sudo|eval|exec)') {
                                    Add-Finding $State 'WARN' 'Hooks' "High-risk lifecycle hook command ($ev): $hname" "cmd=$hcmd; source=$Source"
                                } else {
                                    Add-Finding $State 'REVIEW' 'Hooks' "Lifecycle hook command configured ($ev): $hname" "cmd=$hcmd; matcher=$matcher; source=$Source"
                                }
                            }
                        }
                    }
                }
            }
        }

        # Flat events (PreInvocation, PostInvocation, Stop)
        foreach ($ev in @('PreInvocation', 'PostInvocation', 'Stop')) {
            $evList = Get-Property $hcfg $ev
            if ($evList) {
                foreach ($h in @($evList)) {
                    $htype = [string](Get-Property $h 'type')
                    if (-not $htype) { $htype = 'command' }
                    $hcmd = [string](Get-Property $h 'command')
                    $htimeout = [string](Get-Property $h 'timeout')
                    if (-not $htimeout) { $htimeout = '30' }

                    $State.Hooks.Add([pscustomobject]@{
                        name = $hname
                        event = $ev
                        matcher = 'N/A'
                        type = $htype
                        command = $hcmd
                        enabled = $enabled
                        source = $Source
                        timeout = $htimeout
                    })
                    if ($enabled -eq 'true') {
                        if ($hcmd -match '(?i)(curl|wget|nc|fetch|rm\s+-rf|sudo|eval|exec)') {
                            Add-Finding $State 'WARN' 'Hooks' "High-risk lifecycle hook command ($ev): $hname" "cmd=$hcmd; source=$Source"
                        } else {
                            Add-Finding $State 'REVIEW' 'Hooks' "Lifecycle hook command configured ($ev): $hname" "cmd=$hcmd; source=$Source"
                        }
                    }
                }
            }
        }
    }
}

function Collect-Plugins($State, [string]$PluginsDir, [string]$Source, [string]$ConfigJsonPath = '') {
    if (-not (Test-Path -LiteralPath $PluginsDir -PathType Container)) { return }
    $pdirs = @(Get-ChildItem -LiteralPath $PluginsDir -Directory -ErrorAction SilentlyContinue)
    $configJson = if ($ConfigJsonPath -and (Test-Path -LiteralPath $ConfigJsonPath -PathType Leaf)) { Read-JsonFile $ConfigJsonPath } else { $null }

    foreach ($pdir in $pdirs) {
        $id = $pdir.Name
        $manifestPath = Join-Path $pdir.FullName 'plugin.json'
        $pname = $id
        $pdisabled = 'false'
        $enabled = 'true'
        $features = [Collections.Generic.List[string]]::new()

        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
            $manifest = Read-JsonFile $manifestPath
            if ($manifest) {
                $nameVal = Get-Property $manifest 'name'
                if ($nameVal) { $pname = [string]$nameVal }
                $disVal = Get-Property $manifest 'disabled'
                if ($null -ne $disVal) { $pdisabled = $disVal.ToString().ToLowerInvariant() }
            }
        }

        if ($configJson) {
            $pluginsMap = Get-Property $configJson 'plugins'
            if ($pluginsMap) {
                $pOverride = Get-Property (Get-Property $pluginsMap $id) 'enabled'
                if ($null -ne $pOverride) {
                    $enabled = $pOverride.ToString().ToLowerInvariant()
                } elseif ($pdisabled -eq 'true') {
                    $enabled = 'false'
                }
            } elseif ($pdisabled -eq 'true') {
                $enabled = 'false'
            }
        } elseif ($pdisabled -eq 'true') {
            $enabled = 'false'
        }

        if (Test-Path -LiteralPath (Join-Path $pdir.FullName 'skills') -PathType Container) { $features.Add('skills') }
        if (Test-Path -LiteralPath (Join-Path $pdir.FullName 'rules') -PathType Container -or Test-Path -LiteralPath (Join-Path (Join-Path $pdir.FullName 'rules') 'AGENTS.md') -PathType Leaf) { $features.Add('rules') }
        if (Test-Path -LiteralPath (Join-Path $pdir.FullName 'hooks.json') -PathType Leaf) { $features.Add('hooks') }
        if (Test-Path -LiteralPath (Join-Path $pdir.FullName 'mcp_config.json') -PathType Leaf) { $features.Add('mcp') }

        $featsStr = $features -join ','
        $State.Plugins.Add([pscustomobject]@{
            id = $id
            name = $pname
            enabled = $enabled
            source = $Source
            path = $pdir.FullName
            features = $featsStr
        })

        if ($enabled -eq 'true') {
            Add-Finding $State 'INFO' 'Plugins' "Plugin '$pname' enabled" "features=$featsStr; source=$Source"
            Collect-McpFile $State (Join-Path $pdir.FullName 'mcp_config.json') "plugin:$id"
            Collect-HooksFile $State (Join-Path $pdir.FullName 'hooks.json') "plugin:$id"
            Collect-Customizations $State $pdir.FullName "plugin:$id"
        } else {
            Add-Finding $State 'INFO' 'Plugins' "Plugin '$pname' disabled" "source=$Source"
        }
    }
}

function Collect-JsonConfigs($State, [string]$BaseDir, [string]$Source) {
    foreach ($cname in @('skills.json', 'plugins.json')) {
        $cfile = Join-Path $BaseDir $cname
        if (Test-Path -LiteralPath $cfile -PathType Leaf) {
            Add-SensitiveFile $State $cname $cfile 'REVIEW'
            $json = Read-JsonFile $cfile
            if ($json) {
                $inherits = @(Get-Property $json 'inherits')
                $entries = @(Get-Property $json 'entries')
                if ($inherits.Count -gt 0 -or $entries.Count -gt 0) {
                    Add-Finding $State 'INFO' 'Customizations' "$cname registered" "inherits=$($inherits.Count); entries=$($entries.Count); source=$Source"
                }
            }
        }
    }
}

function Collect-SecuritySettings($State, [string]$Path, [string]$Scope) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Add-SensitiveFile $State "$([IO.Path]::GetFileName($Path)) ($Scope)" $Path 'REVIEW'
    $json = Read-JsonFile $Path
    if ($null -eq $json) { return }

    # 1. Tool execution policy
    $toolPolicy = Get-Property $json 'toolExecutionPolicy'
    if (-not $toolPolicy) { $toolPolicy = Get-Property (Get-Property $json 'general') 'toolExecutionPolicy' }
    if (-not $toolPolicy) { $toolPolicy = Get-Property $json 'autoExecutionPolicy' }
    if ($toolPolicy) {
        $pStr = [string]$toolPolicy
        $rlevel = if ($pStr -eq 'always-proceed') { 'WARN' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'toolExecutionPolicy'
            value = $pStr
            risk_level = $rlevel
        })
        if ($pStr -eq 'always-proceed') {
            Add-Finding $State 'WARN' 'Security Settings' 'Unrestricted tool execution policy enabled (always-proceed)' "scope=$Scope; setting=toolExecutionPolicy"
        } else {
            Add-Finding $State 'INFO' 'Security Settings' "Tool execution policy: $pStr" "scope=$Scope"
        }
    }

    # 2. Terminal Sandbox mode
    $sandboxObj = Get-Property $json 'sandbox'
    $sandboxEnabled = if ($sandboxObj) { Get-Property $sandboxObj 'enabled' } else { Get-Property $json 'terminalSandbox' }
    if ($null -ne $sandboxEnabled) {
        $sStr = $sandboxEnabled.ToString().ToLowerInvariant()
        $rlevel = if ($sStr -eq 'false') { 'WARN' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'sandbox.enabled'
            value = $sStr
            risk_level = $rlevel
        })
        if ($sStr -eq 'false') {
            Add-Finding $State 'WARN' 'Security Settings' 'Terminal command sandboxing is disabled' "scope=$Scope"
        }
    }
    $sandboxNet = if ($sandboxObj) { Get-Property $sandboxObj 'network' } else { Get-Property $json 'networkIsolation' }
    if ($null -ne $sandboxNet) {
        $nStr = $sandboxNet.ToString().ToLowerInvariant()
        $rlevel = if ($nStr -in @('false', 'allow')) { 'REVIEW' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'sandbox.network'
            value = $nStr
            risk_level = $rlevel
        })
        if ($nStr -in @('false', 'allow')) {
            Add-Finding $State 'REVIEW' 'Security Settings' 'Terminal sandbox network isolation is disabled/allowed' "scope=$Scope"
        }
    }

    # 3. Non-workspace file access
    $fileAccess = Get-Property $json 'nonWorkspaceFileAccess'
    if (-not $fileAccess) { $fileAccess = Get-Property $json 'fileAccessPolicy' }
    if ($fileAccess) {
        $faStr = [string]$fileAccess
        $rlevel = if ($faStr -eq 'allow') { 'WARN' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'nonWorkspaceFileAccess'
            value = $faStr
            risk_level = $rlevel
        })
        if ($faStr -eq 'allow') {
            Add-Finding $State 'WARN' 'Security Settings' "Non-workspace file access policy set to 'allow'" "scope=$Scope"
        }
    }

    # 4. Internet access policy
    $netAccess = Get-Property $json 'internetAccessPolicy'
    if (-not $netAccess) { $netAccess = Get-Property $json 'networkAccess' }
    if ($netAccess) {
        $naStr = [string]$netAccess
        $rlevel = if ($naStr -eq 'allow') { 'REVIEW' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'internetAccessPolicy'
            value = $naStr
            risk_level = $rlevel
        })
        if ($naStr -eq 'allow') {
            Add-Finding $State 'REVIEW' 'Security Settings' "Internet access policy set to unrestricted 'allow'" "scope=$Scope"
        }
    }

    # 5. Browser domain policy / allowlist
    $bAllow = Get-Property $json 'browserAllowlist'
    if (-not $bAllow) { $bAllow = Get-Property $json 'browserDomainPolicy' }
    if ($bAllow) {
        $baStr = @($bAllow) -join ','
        $rlevel = if ($baStr -eq '*') { 'REVIEW' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'browserAllowlist'
            value = $baStr
            risk_level = $rlevel
        })
        if ($baStr -eq '*') {
            Add-Finding $State 'REVIEW' 'Security Settings' 'Browser navigation allows all domains (*)' "scope=$Scope"
        }
    }

    # 6. Command allowlist
    $cmdAllow = Get-Property $json 'commandAllowlist'
    if ($cmdAllow) {
        $caStr = @($cmdAllow) -join ','
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'commandAllowlist'
            value = $caStr
            risk_level = 'INFO'
        })
        foreach ($hint in $script:DangerousMcpHints) {
            if ($caStr -match "(?i)\b$hint\b") {
                Add-Finding $State 'WARN' 'Security Settings' "Command allowlist contains risky tool: $hint" "scope=$Scope; allowlist=$caStr"
                break
            }
        }
    }

    # 7. Artifact review mode
    $artReview = Get-Property $json 'artifactReviewMode'
    if ($artReview) {
        $arStr = [string]$artReview
        $rlevel = if ($arStr -eq 'always-proceed') { 'REVIEW' } else { 'INFO' }
        $State.SecuritySettings.Add([pscustomobject]@{
            scope = $Scope
            key = 'artifactReviewMode'
            value = $arStr
            risk_level = $rlevel
        })
        if ($arStr -eq 'always-proceed') {
            Add-Finding $State 'REVIEW' 'Security Settings' "Artifact review mode is set to 'always-proceed'" "scope=$Scope"
        }
    }
}

function Collect-Customizations($State, [string]$ConfigDir, [string]$Source) {
    $skillsDir = Join-Path $ConfigDir 'skills'
    if (Test-Path -LiteralPath $skillsDir -PathType Container) {
        try {
            $skills = @(Get-ChildItem -LiteralPath $skillsDir -Filter 'SKILL.md' -Recurse -File -ErrorAction SilentlyContinue)
            foreach ($file in $skills) {
                $parsed = Parse-SkillFrontmatter $file.FullName
                $State.Skills.Add([pscustomobject]@{
                    source = $Source
                    name = $parsed.name
                    description = $parsed.description
                    path = $file.FullName
                })
                # Check for helper scripts inside skill folder
                $skillFolder = Split-Path $file.FullName -Parent
                $scriptsDir = Join-Path $skillFolder 'scripts'
                if (Test-Path -LiteralPath $scriptsDir -PathType Container) {
                    $scriptFiles = @(Get-ChildItem -LiteralPath $scriptsDir -File -Recurse -ErrorAction SilentlyContinue)
                    if ($scriptFiles.Count -gt 0) {
                        Add-Finding $State 'REVIEW' 'Skills' "Skill '$($parsed.name)' contains custom script files ($($scriptFiles.Count))" "source=$Source; folder=$scriptsDir"
                    }
                }
            }
        } catch {}
    }
    foreach ($rname in @('AGENTS.md', 'GEMINI.md')) {
        $agentsMd = Join-Path $ConfigDir $rname
        if (Test-Path -LiteralPath $agentsMd -PathType Leaf) {
            Add-Finding $State 'INFO' 'Rules' "Rule file defined in $rname" "source=$Source; path=$agentsMd"
        }
    }
    $rulesDir = Join-Path $ConfigDir 'rules'
    if (Test-Path -LiteralPath $rulesDir -PathType Container) {
        $rfiles = @(Get-ChildItem -LiteralPath $rulesDir -Filter '*.md' -File -ErrorAction SilentlyContinue)
        foreach ($rf in $rfiles) {
            Add-Finding $State 'INFO' 'Rules' "Rule file defined in $($rf.Name)" "source=$Source; path=$($rf.FullName)"
        }
    }
}

function Collect-MainConfig($State) {
    $settingsPath = Join-Path $State.AntigravityDir 'settings.json'
    if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
        Collect-SecuritySettings $State $settingsPath 'global'
        $json = Read-JsonFile $settingsPath
        if ($json) {
            $model = Get-Property (Get-Property $json 'model') 'name'
            if (-not $model) { $model = Get-Property $json 'model' }
            if ($model) { Add-Finding $State 'INFO' 'Config' "Default model: $model" }
            $theme = Get-Property $json 'theme'
            if ($theme) { Add-Finding $State 'INFO' 'Config' "Theme: $theme" }
            $sessionRetention = Get-Property (Get-Property $json 'general') 'sessionRetention'
            if ($sessionRetention) {
                $enabled = Get-Property $sessionRetention 'enabled'
                $maxAge = Get-Property $sessionRetention 'maxAge'
                Add-Finding $State 'INFO' 'Config' "Session retention enabled=$($enabled.ToString().ToLowerInvariant()); maxAge=$maxAge"
            }
        }
    } else {
        Add-Finding $State 'INFO' 'Config' 'settings.json not found' $settingsPath
    }

    # App settings
    $appSettings = Join-Path (Join-Path $State.AntigravityDir 'antigravity') 'settings.json'
    if (Test-Path -LiteralPath $appSettings -PathType Leaf) {
        Collect-SecuritySettings $State $appSettings 'app'
    }

    # CLI settings
    $cliSettings = Join-Path (Join-Path $State.AntigravityDir 'antigravity-cli') 'settings.json'
    if (Test-Path -LiteralPath $cliSettings -PathType Leaf) {
        Collect-SecuritySettings $State $cliSettings 'cli'
        $cliJson = Read-JsonFile $cliSettings
        if ($cliJson) {
            $cmodel = Get-Property $cliJson 'model'
            if ($cmodel) { Add-Finding $State 'INFO' 'Config' "CLI model: $cmodel" }
        }
    }
}

function Collect-Projects($State) {
    $projectsPath = Join-Path $State.AntigravityDir 'projects.json'
    if (Test-Path -LiteralPath $projectsPath -PathType Leaf) {
        Add-SensitiveFile $State 'projects.json' $projectsPath 'REVIEW'
        $json = Read-JsonFile $projectsPath
        if ($null -eq $json) {
            Add-Finding $State 'REVIEW' 'Config' 'Unable to parse projects.json' $projectsPath
            return
        }
        $projectsObj = Get-Property $json 'projects'
        foreach ($project in (Get-ObjectEntries $projectsObj)) {
            $path = $project.Name
            $name = [string]$project.Value
            $hasAgents = $false
            if (Test-Path -LiteralPath $path -PathType Container) {
                $agentsDir = Join-Path $path '.agents'
                if (-not (Test-Path -LiteralPath $agentsDir -PathType Container)) {
                    $agentsDir = Join-Path $path '.agent'
                }
                if (Test-Path -LiteralPath $agentsDir -PathType Container) {
                    $hasAgents = $true
                    Collect-Customizations $State $agentsDir "workspace:$name"
                    Collect-McpFile $State (Join-Path $agentsDir 'mcp_config.json') "workspace:$name"
                    Collect-HooksFile $State (Join-Path $agentsDir 'hooks.json') "workspace:$name"
                    Collect-Plugins $State (Join-Path $agentsDir 'plugins') "workspace:$name" (Join-Path $agentsDir 'config.json')
                    Collect-JsonConfigs $State $agentsDir "workspace:$name"
                }
                foreach ($pset in @((Join-Path (Join-Path $path '.gemini') 'settings.json'), (Join-Path (Join-Path $path '.agents') 'settings.json'))) {
                    if (Test-Path -LiteralPath $pset -PathType Leaf) {
                        Collect-SecuritySettings $State $pset "project:$name"
                    }
                }
            }
            $State.Projects.Add([pscustomobject]@{
                path = $path
                name = $name
                has_agents_dir = $hasAgents.ToString().ToLowerInvariant()
            })
        }
        if ($State.Projects.Count -gt 0) {
            Add-Finding $State 'INFO' 'Projects' "$($State.Projects.Count) project(s) registered"
        }
    }
}

function Collect-TrustedFolders($State) {
    $trustedPath = Join-Path $State.AntigravityDir 'trustedFolders.json'
    if (Test-Path -LiteralPath $trustedPath -PathType Leaf) {
        Add-SensitiveFile $State 'trustedFolders.json' $trustedPath 'REVIEW'
        $json = Read-JsonFile $trustedPath
        if ($null -eq $json) {
            Add-Finding $State 'REVIEW' 'Config' 'Unable to parse trustedFolders.json' $trustedPath
            return
        }
        foreach ($entry in (Get-ObjectEntries $json)) {
            $path = $entry.Name
            $level = [string]$entry.Value
            $acl = Get-FileAclSummary $path
            $State.TrustedFolders.Add([pscustomobject]@{
                path = $path
                trust_level = $level
                acl = $acl.Summary
            })
            Add-Finding $State 'WARN' 'Trusted Folders' "Trusted folder grants Antigravity broader workspace autonomy" "path=$path; trust=$level"
        }
        if ($State.TrustedFolders.Count -gt 0) {
            Add-Finding $State 'INFO' 'Trusted Folders' "$($State.TrustedFolders.Count) trusted folder(s) configured"
        }
    }
}

function Collect-Accounts($State) {
    $accountsPath = Join-Path $State.AntigravityDir 'google_accounts.json'
    if (Test-Path -LiteralPath $accountsPath -PathType Leaf) {
        Add-SensitiveFile $State 'google_accounts.json' $accountsPath 'REVIEW'
        $json = Read-JsonFile $accountsPath
        if ($json) {
            $active = Get-Property $json 'active'
            if ($active) {
                Add-Finding $State 'INFO' 'Accounts' "Active Google Account: $(Mask-Email $active)"
            }
        }
    }
}

function Get-DirectoryStats([string]$Path) {
    try {
        $files = @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue)
        $latest = $files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        [pscustomobject]@{
            Count = $files.Count
            Bytes = [long](($files | Measure-Object Length -Sum).Sum)
            Latest = if ($latest) { $latest.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
        }
    } catch {
        [pscustomobject]@{ Count = 0; Bytes = 0L; Latest = '' }
    }
}

function Format-Bytes([long]$Bytes) {
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return '{0:N1} KB' -f ($Bytes / 1KB) }
    if ($Bytes -lt 1GB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    return '{0:N1} GB' -f ($Bytes / 1GB)
}

function Add-RetentionDirectory($State, [string]$Name, [string]$Path, [long]$SizeLimit = 100MB) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $stats = Get-DirectoryStats $Path
    $State.Retention.Add([pscustomobject]@{
        name = $Name
        file_count = [string]$stats.Count
        bytes = [string]$stats.Bytes
        latest_mtime = $stats.Latest
        path = $Path
    })
    Add-Finding $State 'INFO' 'Retention' "$Name contains $($stats.Count) file(s)" "size=$(Format-Bytes $stats.Bytes); latest=$(if ($stats.Latest) {$stats.Latest} else {'none'})"
    if ($stats.Bytes -gt $SizeLimit) {
        Add-Finding $State 'REVIEW' 'Retention' "$Name retained data is larger than $(Format-Bytes $SizeLimit)" (Format-Bytes $stats.Bytes)
    }
    if ($stats.Count -gt 1000) {
        Add-Finding $State 'REVIEW' 'Retention' "$Name contains more than 1000 files" "$($stats.Count) files"
    }
}

function Collect-Retention($State) {
    Add-RetentionDirectory $State 'history' (Join-Path $State.AntigravityDir 'history') 200MB
    Add-RetentionDirectory $State 'tmp' (Join-Path $State.AntigravityDir 'tmp') 200MB
    $antigravitySub = Join-Path $State.AntigravityDir 'antigravity'
    if (Test-Path -LiteralPath $antigravitySub -PathType Container) {
        Add-RetentionDirectory $State 'antigravity-brain' (Join-Path $antigravitySub 'brain') 500MB
    }
    $cliSub = Join-Path $State.AntigravityDir 'antigravity-cli'
    if (Test-Path -LiteralPath $cliSub -PathType Container) {
        Add-RetentionDirectory $State 'antigravity-cli' $cliSub 200MB
    }
}

function Collect-Runtime($State) {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match '(?i)(antigravity|gemini)'
    })
    if ($procs.Count -gt 0) {
        Add-Finding $State 'INFO' 'Runtime' "Active antigravity/gemini process(es) detected: $($procs.Count)"
    }
}

function Convert-StateForOutput($State, [switch]$SummaryOnly) {
    $summary = Get-Summary $State
    $base = [ordered]@{
        timestamp = $State.Timestamp
        hostname = $State.Hostname
        username = Get-DisplayText $State $State.User
        antigravity_dir = Get-DisplayText $State $State.AntigravityDir
        summary = $summary
    }
    if (-not $SummaryOnly) {
        $base.findings = @($State.Findings | ForEach-Object {
            [ordered]@{
                severity = $_.severity
                section = $_.section
                message = Get-DisplayText $State $_.message
                detail = Get-DisplayText $State $_.detail
            }
        })
        foreach ($pair in @(
            @('mcp_servers', 'McpServers'), @('hooks', 'Hooks'), @('plugins', 'Plugins'),
            @('security_settings', 'SecuritySettings'), @('trusted_folders', 'TrustedFolders'),
            @('projects', 'Projects'), @('skills', 'Skills'), @('sensitive_files', 'SensitiveFiles'),
            @('retention', 'Retention')
        )) {
            $base[$pair[0]] = @($State[$pair[1]] | ForEach-Object {
                $copy = [ordered]@{}
                foreach ($property in $_.PSObject.Properties) {
                    $copy[$property.Name] = Get-DisplayText $State $property.Value
                }
                [pscustomobject]$copy
            })
        }
    }
    [pscustomobject]$base
}

function Compare-Snapshots($CurrentObj, [string]$BaselinePath) {
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
        [Console]::Error.WriteLine("Error: cannot read baseline: $BaselinePath")
        exit 1
    }
    $baseObj = Read-JsonFile $BaselinePath
    if ($null -eq $baseObj) {
        [Console]::Error.WriteLine("Error: unable to parse baseline JSON: $BaselinePath")
        exit 1
    }

    $diffResult = [ordered]@{
        changed = [Collections.Generic.List[object]]::new()
        has_changes = $false
    }

    $sections = @(
        @{ Name = 'mcp_servers'; Key = 'name' },
        @{ Name = 'hooks'; Key = 'name' },
        @{ Name = 'plugins'; Key = 'id' },
        @{ Name = 'security_settings'; Key = 'key' },
        @{ Name = 'trusted_folders'; Key = 'path' },
        @{ Name = 'projects'; Key = 'path' },
        @{ Name = 'skills'; Key = 'name' }
    )

    foreach ($sec in $sections) {
        $sName = $sec.Name
        $sKey = $sec.Key
        $oldItems = @(Get-Property $baseObj $sName | ForEach-Object { [string](Get-Property $_ $sKey) } | Where-Object { $_ } | Select-Object -Unique)
        $newItems = @(Get-Property $CurrentObj $sName | ForEach-Object { [string](Get-Property $_ $sKey) } | Where-Object { $_ } | Select-Object -Unique)

        $added = @($newItems | Where-Object { $_ -notin $oldItems } | Sort-Object)
        $removed = @($oldItems | Where-Object { $_ -notin $newItems } | Sort-Object)

        if ($added.Count -gt 0 -or $removed.Count -gt 0) {
            $diffResult.changed.Add([ordered]@{
                section = $sName
                added = $added
                removed = $removed
            })
        }
    }

    $diffResult.has_changes = $diffResult.changed.Count -gt 0
    $diffResult
}

function Write-TerminalReport($State) {
    $summary = Get-Summary $State
    if ($script:Options.Summary) {
        Write-Output "$(Get-DisplayText $State $State.User)  WARN=$($summary.warn) REVIEW=$($summary.review) INFO=$($summary.info)  $(Get-DisplayText $State $State.AntigravityDir)"
        $shown = 0
        foreach ($finding in $State.Findings) {
            if ($finding.severity -eq 'INFO') { continue }
            Write-Output "  [$($finding.severity)] $($finding.section): $(Get-DisplayText $State $finding.message)"
            if (++$shown -ge 8) { break }
        }
        return
    }
    Write-Output ''
    Write-Output "ANTIGRAVITY-AUDIT v$($script:Version) - Antigravity local security audit (Windows)"
    Write-Output "User: $(Get-DisplayText $State $State.User)"
    Write-Output "Antigravity home: $(Get-DisplayText $State $State.AntigravityDir)"
    Write-Output "Findings: WARN=$($summary.warn) REVIEW=$($summary.review) INFO=$($summary.info)"
    Write-Output ''
    if (-not $script:Options.Quiet -or $summary.warn -gt 0 -or $summary.review -gt 0) {
        Write-Output 'Findings'
        foreach ($finding in $State.Findings) {
            if ($script:Options.Quiet -and $finding.severity -eq 'INFO') { continue }
            Write-Output ('  [{0}] {1,-16} {2}' -f $finding.severity, $finding.section, (Get-DisplayText $State $finding.message))
            if ($finding.detail) { Write-Output "       $(Get-DisplayText $State $finding.detail)" }
        }
        Write-Output ''
    }
    foreach ($section in @(
        @('MCP Servers', 'McpServers', 'name'),
        @('Lifecycle Hooks', 'Hooks', 'name'),
        @('Plugins', 'Plugins', 'name'),
        @('Security Settings', 'SecuritySettings', 'key'),
        @('Trusted Folders', 'TrustedFolders', 'path'),
        @('Projects', 'Projects', 'path'),
        @('Skills', 'Skills', 'name'),
        @('Sensitive Files', 'SensitiveFiles', 'name'),
        @('Retention', 'Retention', 'name')
    )) {
        Write-Output $section[0]
        $items = @($State[$section[1]])
        if ($items.Count -eq 0) { Write-Output '  none' }
        else {
            foreach ($item in $items) {
                $first = Get-DisplayText $State $item.($section[2])
                $detail = ($item.PSObject.Properties | Where-Object Name -ne $section[2] | ForEach-Object {
                    "$($_.Name)=$(Get-DisplayText $State $_.Value)"
                }) -join ' '
                Write-Output ('  {0,-22} {1}' -f $first, $detail)
            }
        }
        Write-Output ''
    }
}

function ConvertTo-HtmlEncoded([AllowNull()][object]$Value) {
    [Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-HtmlReport($States) {
    $builder = [Text.StringBuilder]::new()
    [void]$builder.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ANTIGRAVITY-AUDIT Report</title>')
    [void]$builder.AppendLine('<style>body{margin:0;background:#0d1117;color:#e6edf3;font-family:"Segoe UI",sans-serif}main{max-width:1180px;margin:auto;padding:32px 20px}h2{margin-top:28px}.meta{color:#8b949e}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}.summary div{background:#161b22;border:1px solid #30363d;padding:12px}.summary span{display:block;color:#8b949e}.summary strong{font-size:24px}table{width:100%;border-collapse:collapse;border:1px solid #30363d;margin-bottom:20px}th,td{padding:9px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top;font-size:13px}th{color:#8b949e;background:#161b22}code{color:#cae8ff;white-space:pre-wrap;word-break:break-word}.badge{padding:2px 6px;font-weight:700}.WARN{background:#5c1f1f;color:#ffa198}.REVIEW{background:#3d2f00;color:#f0c846}.INFO{background:#0c2a4a;color:#79c0ff}</style></head><body><main>')
    foreach ($state in $States) {
        $summary = Get-Summary $state
        [void]$builder.AppendLine("<section><h1>ANTIGRAVITY-AUDIT</h1><p class=`"meta`">User: <strong>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $state.User))</strong> &middot; Host: <strong>$(ConvertTo-HtmlEncoded $state.Hostname)</strong> &middot; Generated: <strong>$(ConvertTo-HtmlEncoded $state.Timestamp)</strong></p>")
        [void]$builder.AppendLine("<p class=`"meta`">Antigravity home: <code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $state.AntigravityDir))</code></p><div class=`"summary`"><div><span>WARN</span><strong>$($summary.warn)</strong></div><div><span>REVIEW</span><strong>$($summary.review)</strong></div><div><span>INFO</span><strong>$($summary.info)</strong></div></div>")
        [void]$builder.AppendLine('<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>')
        foreach ($finding in $state.Findings) {
            if ($script:Options.Quiet -and $finding.severity -eq 'INFO') { continue }
            [void]$builder.AppendLine("<tr><td><span class=`"badge $($finding.severity)`">$($finding.severity)</span></td><td>$(ConvertTo-HtmlEncoded $finding.section)</td><td>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $finding.message))</td><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $finding.detail))</code></td></tr>")
        }
        [void]$builder.AppendLine('</tbody></table>')

        if ($state.McpServers.Count -gt 0) {
            [void]$builder.AppendLine('<h2>MCP Servers</h2><table><thead><tr><th>Name</th><th>Type</th><th>Command / URL</th><th>Env Keys</th><th>Source</th></tr></thead><tbody>')
            foreach ($m in $state.McpServers) {
                [void]$builder.AppendLine("<tr><td>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $m.name))</td><td>$(ConvertTo-HtmlEncoded $m.type)</td><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $m.command_or_url))</code></td><td>$(ConvertTo-HtmlEncoded $m.env_keys)</td><td>$(ConvertTo-HtmlEncoded $m.source)</td></tr>")
            }
            [void]$builder.AppendLine('</tbody></table>')
        }

        if ($state.Hooks.Count -gt 0) {
            [void]$builder.AppendLine('<h2>Lifecycle Hooks</h2><table><thead><tr><th>Name</th><th>Event</th><th>Matcher</th><th>Command</th><th>Enabled</th><th>Source</th></tr></thead><tbody>')
            foreach ($h in $state.Hooks) {
                [void]$builder.AppendLine("<tr><td>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $h.name))</td><td>$(ConvertTo-HtmlEncoded $h.event)</td><td>$(ConvertTo-HtmlEncoded $h.matcher)</td><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $h.command))</code></td><td>$(ConvertTo-HtmlEncoded $h.enabled)</td><td>$(ConvertTo-HtmlEncoded $h.source)</td></tr>")
            }
            [void]$builder.AppendLine('</tbody></table>')
        }

        if ($state.Plugins.Count -gt 0) {
            [void]$builder.AppendLine('<h2>Plugins</h2><table><thead><tr><th>ID</th><th>Name</th><th>Enabled</th><th>Features</th><th>Source</th></tr></thead><tbody>')
            foreach ($p in $state.Plugins) {
                [void]$builder.AppendLine("<tr><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $p.id))</code></td><td>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $p.name))</td><td>$(ConvertTo-HtmlEncoded $p.enabled)</td><td><code>$(ConvertTo-HtmlEncoded $p.features)</code></td><td>$(ConvertTo-HtmlEncoded $p.source)</td></tr>")
            }
            [void]$builder.AppendLine('</tbody></table>')
        }

        if ($state.SecuritySettings.Count -gt 0) {
            [void]$builder.AppendLine('<h2>Security Settings</h2><table><thead><tr><th>Scope</th><th>Setting</th><th>Value</th><th>Risk</th></tr></thead><tbody>')
            foreach ($s in $state.SecuritySettings) {
                [void]$builder.AppendLine("<tr><td>$(ConvertTo-HtmlEncoded $s.scope)</td><td><code>$(ConvertTo-HtmlEncoded $s.key)</code></td><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $s.value))</code></td><td><span class=`"badge $($s.risk_level)`">$($s.risk_level)</span></td></tr>")
            }
            [void]$builder.AppendLine('</tbody></table>')
        }

        [void]$builder.AppendLine('</section>')
    }
    [void]$builder.AppendLine('</main></body></html>')
    $builder.ToString()
}

function Get-AuditTargets {
    if ($script:Options.AllUsers) {
        return @(Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object {
                Test-Path -LiteralPath (Join-Path $_.FullName $script:AntigravityDirName) -PathType Container
            } | ForEach-Object {
                [pscustomobject]@{ User = $_.Name; Home = $_.FullName }
            })
    }
    $user = if ($script:Options.User) { $script:Options.User } else { [Environment]::UserName }
    $userHome = if ($script:Options.User -and $script:Options.User -ne [Environment]::UserName) {
        Join-Path (Join-Path $env:SystemDrive 'Users') $script:Options.User
    } else {
        [Environment]::GetFolderPath('UserProfile')
    }
    @([pscustomobject]@{ User = $user; Home = $userHome })
}

function Invoke-Audit([string]$UserName, [string]$HomeDir) {
    $antigravityDir = if ($script:Options.AntigravityDir) {
        (Resolve-Path -LiteralPath $script:Options.AntigravityDir).Path
    } else {
        Join-Path $HomeDir $script:AntigravityDirName
    }
    if ($script:Options.AntigravityDir) { $HomeDir = Split-Path -Parent $antigravityDir }
    $state = New-AuditState $UserName $HomeDir $antigravityDir

    if (-not (Test-Path -LiteralPath $antigravityDir -PathType Container)) {
        Add-Finding $state 'INFO' 'General' 'Antigravity data not found' $antigravityDir
        Collect-Runtime $state
        return $state
    }

    Collect-MainConfig $state
    Collect-Projects $state
    Collect-TrustedFolders $state
    Collect-Accounts $state

    # Collect global customizations
    $globalConfig = Join-Path $antigravityDir 'config'
    if (Test-Path -LiteralPath $globalConfig -PathType Container) {
        Collect-Customizations $state $globalConfig 'global'
        Collect-McpFile $state (Join-Path $globalConfig 'mcp_config.json') 'global'
        Collect-HooksFile $state (Join-Path $globalConfig 'hooks.json') 'global'
        Collect-Plugins $state (Join-Path $globalConfig 'plugins') 'global' (Join-Path $globalConfig 'config.json')
        Collect-JsonConfigs $state $globalConfig 'global'
    }

    # Sensitive files collection
    Add-SensitiveFile $state 'oauth_creds.json' (Join-Path $antigravityDir 'oauth_creds.json') 'WARN'
    Add-SensitiveFile $state 'installation_id' (Join-Path $antigravityDir 'installation_id') 'REVIEW'
    Add-SensitiveFile $state 'user_id' (Join-Path $antigravityDir 'user_id') 'REVIEW'

    Collect-Retention $state
    Collect-Runtime $state

    $state
}

$targets = @(Get-AuditTargets)
if ($targets.Count -eq 0) {
    [Console]::Error.WriteLine('No users with Antigravity data found.')
    exit 1
}

$states = @($targets | ForEach-Object { Invoke-Audit $_.User $_.Home })

if ($script:Options.Diff) {
    $currentObj = Convert-StateForOutput $states[0]
    $diffObj = Compare-Snapshots $currentObj $script:Options.Diff
    if ($script:Options.DiffJson) {
        $diffObj | ConvertTo-Json -Depth 10
    } else {
        if (-not $diffObj.has_changes) {
            Write-Output 'No baseline differences detected.'
        } else {
            foreach ($sec in $diffObj.changed) {
                Write-Output "## $($sec.section)"
                if ($sec.added.Count -gt 0) {
                    Write-Output 'Added:'
                    foreach ($a in $sec.added) { Write-Output "  + $a" }
                }
                if ($sec.removed.Count -gt 0) {
                    Write-Output 'Removed:'
                    foreach ($r in $sec.removed) { Write-Output "  - $r" }
                }
            }
        }
    }
    exit 0
}

$content = if ($script:Options.Json) {
    $objects = @($states | ForEach-Object { Convert-StateForOutput $_ -SummaryOnly:$script:Options.Summary })
    $jsonObject = if ($objects.Count -eq 1) { $objects[0] } else { $objects }
    $jsonObject | ConvertTo-Json -Depth 12
} elseif ($script:Options.Html) {
    New-HtmlReport $states
} else {
    $lines = @($states | ForEach-Object { Write-TerminalReport $_ })
    $lines -join [Environment]::NewLine
}

if ($script:Options.Html) {
    $path = if ($script:Options.Output) { $script:Options.Output }
        elseif ($script:Options.Html -eq 'AUTO') { "antigravity_audit_$([DateTime]::Now.ToString('yyyyMMdd_HHmmss')).html" }
        else { $script:Options.Html }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($path), $content, [Text.UTF8Encoding]::new($false))
    Write-Output "HTML report written: $path"
} elseif ($script:Options.Output) {
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($script:Options.Output), $content, [Text.UTF8Encoding]::new($false))
} else {
    Write-Output $content
}

$exitCode = 0
foreach ($state in $states) {
    $summary = Get-Summary $state
    if ($script:Options.FailOn -eq 'warn' -and $summary.warn -gt 0) { $exitCode = 2 }
    elseif ($script:Options.FailOn -eq 'review' -and $summary.review -gt 0 -and $exitCode -eq 0) { $exitCode = 1 }
}
exit $exitCode
