#!/bin/sh
# Dispatch: `scan ...` (or -h/--help) runs the headless CLI, `serve` or no
# args runs the API server, anything else is exec'd verbatim so callers can
# still override the command entirely.
set -e

case "$1" in
    scan|-h|--help)
        exec python -m app.cli "$@"
        ;;
    ""|serve)
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000
        ;;
    *)
        exec "$@"
        ;;
esac
