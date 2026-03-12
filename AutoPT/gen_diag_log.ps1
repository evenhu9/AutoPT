# Save as: tools\gen_diag_log.ps1
# Usage:
#   pwsh -File .\tools\gen_diag_log.ps1
#   pwsh -File .\tools\gen_diag_log.ps1 -InputPath "..\Entering new AgentExecutor chain...txt" -ConfigPath ".\config\config.yml"

param(
    [string]$InputPath = ".\Entering new AgentExecutor chain...txt",
    [string]$ConfigPath = ".\config\config.yml",
    [string]$OutputPath = ".\diagnostic_summary.txt"
)

function Resolve-FirstExistingPath {
    param([string[]]$Candidates)
    foreach ($p in $Candidates) {
        if (Test-Path $p) { return (Resolve-Path $p).Path }
    }
    return $null
}

function Unescape-LogText {
    param([string]$Text)
    if (-not $Text) { return "" }
    $t = $Text -replace "\\r","" -replace "\\n","`n" -replace "\\'","'"
    return $t
}

function Get-ExploitSummary {
    param([string]$RawText)

    $pattern = "- message -> \[AIMessage\(content='(?<content>.*?)'\)\]\s*- sender -> 'Exploit'"
    $matches = [regex]::Matches($RawText, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    $items = @()
    foreach ($m in $matches) {
        $content = Unescape-LogText $m.Groups["content"].Value

        $actionInput = ""
        $ai = [regex]::Match($content, "Action Input:\s*(.+?)(`n|$)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($ai.Success) { $actionInput = $ai.Groups[1].Value.Trim() }

        $sigPattern = '(InvalidIndexNameException\[[^\n]+|SearchParseException\[[^\n]+|Parse Failure|No body content found|Command execution timeout|\"error\"\s*:\s*\"[^\"]+\"|\"status\"\s*:\s*\d+|Exception[^\n]*)'
        $sigMatches = [regex]::Matches($content, $sigPattern)
        $signals = @()
        foreach ($s in $sigMatches) {
            $v = $s.Value.Trim()
            if ($v -and ($signals -notcontains $v)) { $signals += $v }
        }

        $obj = [PSCustomObject]@{
            ActionInput = $actionInput
            Signals     = ($signals -join " | ")
        }
        $items += $obj
    }

    if ($items.Count -gt 2) { return $items[($items.Count-2)..($items.Count-1)] }
    return $items
}

function Get-CheckSummary {
    param([string]$RawText)

    $pattern = "- message -> \[HumanMessage\(content='(?<content>.*?)'\)\]\s*- sender -> 'Check'"
    $matches = [regex]::Matches($RawText, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    $items = @()
    foreach ($m in $matches) {
        $content = Unescape-LogText $m.Groups["content"].Value
        $summary = ""
        $sm = [regex]::Match($content, "Last observation summary:\s*(.+)$", [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($sm.Success) {
            $summary = $sm.Groups[1].Value.Trim()
        } else {
            $summary = $content.Trim()
        }
        if ($summary.Length -gt 500) { $summary = $summary.Substring(0, 500) + " ...[truncated]" }

        $items += $summary
    }

    if ($items.Count -gt 2) { return $items[($items.Count-2)..($items.Count-1)] }
    return $items
}

function Get-SelectedVuln {
    param([string]$RawText)

    $pat = "I think we can try this vulnerability\. The vulnerability information is as follows (?<v>\{.*?\})"
    $ms = [regex]::Matches($RawText, $pat, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($ms.Count -eq 0) { return "N/A" }
    $last = $ms[$ms.Count - 1].Groups["v"].Value
    return (Unescape-LogText $last).Trim()
}

function Get-LastCheckpoint {
    param([string]$RawText)

    $cpMatches = [regex]::Matches($RawText, "\[-2:checkpoint\] State at the end of step -2:\s*(?<blk>\{.*?)(?=\n\[\d+:tasks\]|\Z)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($cpMatches.Count -eq 0) {
        return [PSCustomObject]@{ check_count="N/A"; sender="N/A"; first_vuln="N/A" }
    }

    $blk = $cpMatches[$cpMatches.Count - 1].Groups["blk"].Value

    $cc = "N/A"
    $sd = "N/A"
    $fv = "N/A"

    $m1 = [regex]::Match($blk, "'check_count':\s*(\d+)")
    if ($m1.Success) { $cc = $m1.Groups[1].Value }

    $m2 = [regex]::Match($blk, "'sender':\s*'([^']+)'")
    if ($m2.Success) { $sd = $m2.Groups[1].Value }

    $m3 = [regex]::Match($blk, "'vulntype':\s*'([^']+)'")
    if ($m3.Success) { $fv = $m3.Groups[1].Value }

    return [PSCustomObject]@{
        check_count = $cc
        sender      = $sd
        first_vuln  = $fv
    }
}

function Get-PsmConfig {
    param([string]$CfgPath)

    if (-not (Test-Path $CfgPath)) { return "psm config not found: $CfgPath" }

    $lines = Get-Content -Path $CfgPath
    $keys = @("sys_iterations","exp_iterations","query_iterations","scan_iterations")
    $out = @()
    foreach ($k in $keys) {
        $m = $lines | Select-String -Pattern "^\s*$k\s*:\s*(.+)$" | Select-Object -First 1
        if ($m) { $out += "$k: $($m.Matches[0].Groups[1].Value.Trim())" }
    }
    return ($out -join "`n")
}

# Resolve paths from common working directories
$resolvedInput = Resolve-FirstExistingPath @(
    $InputPath,
    ".\Entering new AgentExecutor chain...txt",
    "..\Entering new AgentExecutor chain...txt"
)
if (-not $resolvedInput) {
    throw "Cannot find log file. Tried: $InputPath, .\Entering new AgentExecutor chain...txt, ..\Entering new AgentExecutor chain...txt"
}

$resolvedConfig = Resolve-FirstExistingPath @(
    $ConfigPath,
    ".\config\config.yml",
    "..\AutoPT\config\config.yml",
    ".\AutoPT\config\config.yml"
)

$raw = Get-Content -Path $resolvedInput -Raw

$selectedVuln = Get-SelectedVuln -RawText $raw
$exploitItems = Get-ExploitSummary -RawText $raw
$checkItems   = Get-CheckSummary -RawText $raw
$checkpoint   = Get-LastCheckpoint -RawText $raw
$psmCfg       = if ($resolvedConfig) { Get-PsmConfig -CfgPath $resolvedConfig } else { "psm config not found" }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("=== COMPACT DIAGNOSTIC LOG ===")
[void]$sb.AppendLine("SourceLog: $resolvedInput")
[void]$sb.AppendLine("Config: " + ($(if ($resolvedConfig) { $resolvedConfig } else { "N/A" })))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("[1] Selected Vulnerability")
[void]$sb.AppendLine($selectedVuln)
[void]$sb.AppendLine("")
[void]$sb.AppendLine("[2] Last 2 Exploit Attempts (Action Input + error/status)")
if ($exploitItems.Count -eq 0) {
    [void]$sb.AppendLine("N/A")
} else {
    $idx = 1
    foreach ($it in $exploitItems) {
        [void]$sb.AppendLine("Exploit#$idx")
        [void]$sb.AppendLine("Action Input: " + $it.ActionInput)
        [void]$sb.AppendLine("Signals: " + $(if ($it.Signals) { $it.Signals } else { "N/A" }))
        [void]$sb.AppendLine("")
        $idx++
    }
}
[void]$sb.AppendLine("[3] Last 2 Check Summaries")
if ($checkItems.Count -eq 0) {
    [void]$sb.AppendLine("N/A")
} else {
    $i = 1
    foreach ($c in $checkItems) {
        [void]$sb.AppendLine("Check#$i: $c")
        $i++
    }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("[4] Final Checkpoint")
[void]$sb.AppendLine("check_count: $($checkpoint.check_count)")
[void]$sb.AppendLine("sender: $($checkpoint.sender)")
[void]$sb.AppendLine("first_vuln: $($checkpoint.first_vuln)")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("[5] PSM Config")
[void]$sb.AppendLine($psmCfg)

$summary = $sb.ToString()
$summary | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Generated: $OutputPath"
Write-Host "---- Preview ----"
Write-Host $summary