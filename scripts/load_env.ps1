param(
    [string]$EnvPath = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$AllowedNames = @("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY")

try {
    if (-not (Test-Path -LiteralPath $EnvPath -PathType Leaf)) {
        throw "Environment file not found: $EnvPath"
    }

    foreach ($name in $AllowedNames) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }

    $seen = @{}
    foreach ($line in Get-Content -LiteralPath $EnvPath) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }
        if ($trimmed -notmatch "^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$") {
            throw "Invalid environment assignment"
        }
        $name = $Matches[1]
        $value = $Matches[2].Trim()
        if ($name -notin $AllowedNames) {
            throw "Unsupported environment variable: $name"
        }
        if ($seen.ContainsKey($name)) {
            throw "Duplicate environment variable: $name"
        }
        $seen[$name] = $true
        if ($value.StartsWith('"') -or $value.StartsWith("'")) {
            $quote = $value[0]
            $closingQuote = $value.IndexOf($quote, 1)
            if ($closingQuote -lt 1) {
                throw "Unterminated quoted value for $name"
            }
            $suffix = $value.Substring($closingQuote + 1).Trim()
            if ($suffix -and -not $suffix.StartsWith("#")) {
                throw "Invalid trailing content for $name"
            }
            $value = $value.Substring(1, $closingQuote - 1)
        }
        else {
            $value = [regex]::Replace($value, "\s+#.*$", "").TrimEnd()
        }
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }

    foreach ($name in $AllowedNames) {
        $state = if ([Environment]::GetEnvironmentVariable($name, "Process")) { "set" } else { "NOT SET" }
        Write-Output "${name}: $state"
    }
}
catch {
    [Console]::Error.WriteLine("ERROR: $($_.Exception.Message)")
    exit 1
}
