#Requires -Version 5.1
<#
    Example rotation script: roughly half of all rotations fail. Rotates nothing.
#>

param([Parameter(Mandatory)][string]$Operation)

$ErrorActionPreference = 'Stop'

$null = [Console]::In.ReadToEnd()

if ($Operation -ne 'rotate') 
{ 
    exit 0 
}

if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) 
{ 
    exit 0 
}

exit 1
