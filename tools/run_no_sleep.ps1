param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"

$signature = @"
using System;
using System.Runtime.InteropServices;

public static class PowerRequest {
    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint esFlags);
}
"@

Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue

$ES_CONTINUOUS = [UInt32]2147483648
$ES_SYSTEM_REQUIRED = [UInt32]1

try {
    [void][PowerRequest]::SetThreadExecutionState([UInt32]($ES_CONTINUOUS -bor $ES_SYSTEM_REQUIRED))
    Write-Host "Sleep prevention enabled for this process. Windows lock policy is unchanged."
    Write-Host "Running: $Command $($Arguments -join ' ')"

    & $Command @Arguments
    exit $LASTEXITCODE
}
finally {
    [void][PowerRequest]::SetThreadExecutionState($ES_CONTINUOUS)
    Write-Host "Sleep prevention released."
}
