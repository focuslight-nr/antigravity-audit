# ANTIGRAVITY-AUDIT - Antigravity local security audit tool (Windows/PowerShell)
# Read-only audit for ~/.gemini configuration, projects, trusted folders, and sensitive files.
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'
$script:Version = '0.1.0'
$script:AntigravityDirName = '.gemini'

$script:Options = @{
    Json = $false
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
       [--fail-on warn|review] [--redact-paths] [--user USER] [--all-users]
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
        { $_ -in @('--output', '--fail-on', '--user', '--antigravity-dir') } {
            if (($i + 1) -ge $CliArgs.Count) { Exit-ArgumentError "Missing value for $arg" }
            $i++
            $value = $CliArgs[$i]
            switch ($arg) {
                '--output' { $script:Options.Output = $value }
                '--fail-on' { $script:Options.FailOn = $value.ToLowerInvariant() }
                '--user' { $script:Options.User = $value }
                '--antigravity-dir' { $script:Options.AntigravityDir = $value }
            }
        }
        default { Exit-ArgumentError "Unknown option: $arg" }
    }
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
    $agentsMd = Join-Path $ConfigDir 'AGENTS.md'
    if (Test-Path -LiteralPath $agentsMd -PathType Leaf) {
        Add-Finding $State 'INFO' 'Skills' "Custom system rules defined in AGENTS.md" "source=$Source; path=$agentsMd"
    }
}

function Collect-MainConfig($State) {
    $settingsPath = Join-Path $State.AntigravityDir 'settings.json'
    if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
        Add-SensitiveFile $State 'settings.json' $settingsPath 'REVIEW'
        $json = Read-JsonFile $settingsPath
        if ($null -eq $json) {
            Add-Finding $State 'REVIEW' 'Config' 'Unable to parse settings.json' $settingsPath
        } else {
            $model = Get-Property (Get-Property $json 'model') 'name'
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
                if (Test-Path -LiteralPath $agentsDir -PathType Container) {
                    $hasAgents = $true
                    Collect-Customizations $State $agentsDir "workspace:$name"
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
}

function Collect-Runtime($State) {
    # Check for running processes that could be antigravity / gemini related
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
            @('trusted_folders', 'TrustedFolders'), @('projects', 'Projects'),
            @('skills', 'Skills'), @('sensitive_files', 'SensitiveFiles'),
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
        @('Trusted Folders', 'TrustedFolders', 'path'), @('Projects', 'Projects', 'path'),
        @('Skills', 'Skills', 'name'), @('Sensitive Files', 'SensitiveFiles', 'name'),
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
    [void]$builder.AppendLine('<style>body{margin:0;background:#0d1117;color:#e6edf3;font-family:"Segoe UI",sans-serif}main{max-width:1180px;margin:auto;padding:32px 20px}h2{margin-top:28px}.meta{color:#8b949e}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}.summary div{background:#161b22;border:1px solid #30363d;padding:12px}.summary span{display:block;color:#8b949e}.summary strong{font-size:24px}table{width:100%;border-collapse:collapse;border:1px solid #30363d}th,td{padding:9px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top;font-size:13px}th{color:#8b949e;background:#161b22}code{color:#cae8ff;white-space:pre-wrap;word-break:break-word}.badge{padding:2px 6px;font-weight:700}.WARN{background:#5c1f1f;color:#ffa198}.REVIEW{background:#3d2f00;color:#f0c846}.INFO{background:#0c2a4a;color:#79c0ff}</style></head><body><main>')
    foreach ($state in $States) {
        $summary = Get-Summary $state
        [void]$builder.AppendLine("<section><h1>ANTIGRAVITY-AUDIT</h1><p class=`"meta`">User: <strong>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $state.User))</strong> &middot; Host: <strong>$(ConvertTo-HtmlEncoded $state.Hostname)</strong> &middot; Generated: <strong>$(ConvertTo-HtmlEncoded $state.Timestamp)</strong></p>")
        [void]$builder.AppendLine("<p class=`"meta`">Antigravity home: <code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $state.AntigravityDir))</code></p><div class=`"summary`"><div><span>WARN</span><strong>$($summary.warn)</strong></div><div><span>REVIEW</span><strong>$($summary.review)</strong></div><div><span>INFO</span><strong>$($summary.info)</strong></div></div>")
        [void]$builder.AppendLine('<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>')
        foreach ($finding in $state.Findings) {
            if ($script:Options.Quiet -and $finding.severity -eq 'INFO') { continue }
            [void]$builder.AppendLine("<tr><td><span class=`"badge $($finding.severity)`">$($finding.severity)</span></td><td>$(ConvertTo-HtmlEncoded $finding.section)</td><td>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $finding.message))</td><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $finding.detail))</code></td></tr>")
        }
        [void]$builder.AppendLine('</tbody></table></section>')
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
