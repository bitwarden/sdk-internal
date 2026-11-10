# Fixture: blocks without ever reading stdin, so a payload larger than the pipe buffer leaves
# the connector's write blocked. Proves the timeout covers the write as well as the wait.

param([string]$Operation)

$ErrorActionPreference = 'Stop'

while ($true) {
    Start-Sleep -Seconds 3600
}
