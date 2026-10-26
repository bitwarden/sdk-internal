#Requires -Version 5.1
<#
    Example rotation script: always reports success. Rotates nothing.
#>

param([Parameter(Mandatory)][string]$Operation)

$ErrorActionPreference = 'Stop'
$null = [Console]::In.ReadToEnd()
exit 0
