#!/bin/bash
set -e

if [ -z "$ROOT_PATH" ] || [ "$ROOT_PATH" = "/" ]; then
    export ROOT_PATH=""
else
    [[ "$ROOT_PATH" != /* ]] && ROOT_PATH="/$ROOT_PATH"
    export ROOT_PATH="${ROOT_PATH%/}"
fi

echo "Initializing ThePhish framework at Base Path: '${ROOT_PATH:-/}'"

envsubst '$DFIR_IRIS_URL $CORTEX_URL $ROOT_PATH' < /opt/thephish/templates/index.html > /opt/thephish/templates/index.tmp
mv /opt/thephish/templates/index.tmp /opt/thephish/templates/index.html

envsubst '$ROOT_PATH' < /opt/thephish/static/assets/js/thephish.js > /opt/thephish/static/assets/js/thephish.tmp
mv /opt/thephish/static/assets/js/thephish.tmp /opt/thephish/static/assets/js/thephish.js

envsubst '$ROOT_PATH' < /opt/thephish/static/assets/css/fonts.css > /opt/thephish/static/assets/css/fonts.tmp
mv /opt/thephish/static/assets/css/fonts.tmp /opt/thephish/static/assets/css/fonts.css

envsubst '$ROOT_PATH' < /opt/thephish/static/assets/bootstrap/css/bootstrap.min.css > /opt/thephish/static/assets/bootstrap/css/bootstrap.min.tmp
mv /opt/thephish/static/assets/bootstrap/css/bootstrap.min.tmp /opt/thephish/static/assets/bootstrap/css/bootstrap.min.css

envsubst '$ROOT_PATH' < /opt/thephish/thephish_app.py > /opt/thephish/thephish_app.tmp
mv /opt/thephish/thephish_app.tmp /opt/thephish/thephish_app.py

exec /opt/thephish/.venv/bin/python3 thephish_app.py