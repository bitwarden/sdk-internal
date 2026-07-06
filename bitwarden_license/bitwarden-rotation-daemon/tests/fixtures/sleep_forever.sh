#!/bin/sh
# Fixture: sleeps indefinitely.
#
# Used to exercise the timeout-and-kill path in the custom-script integration.
# The daemon kills the process when the timeout fires.

exec sleep 3600
