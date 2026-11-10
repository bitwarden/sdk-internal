# Fixture: blocks without ever reading stdin, so a payload larger than the pipe buffer leaves
# the connector's write blocked. Proves the write is inside the timeout, not just the wait.

param([string]$Operation)

$ErrorActionPreference = 'Stop'

while ($true) {
    Start-Sleep -Seconds 3600
}
