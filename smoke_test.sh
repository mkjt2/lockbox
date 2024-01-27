#!/usr/bin/env bash

set -e

export LOCKBOX_SIGNING_KEY_FILE=signing_key.txt
export LOCKBOX_CONFIG_PATH=sample_config.json

poetry run gunicorn lockbox.app:app --preload &

APP_PID=$!

echo "Server started"

trap "kill $APP_PID" EXIT

sleep 2

curl -vf localhost:8000/s/github_public/orgs/google/repos
echo
echo

echo "OK [GET/public/no token]"

export SERVICE_TOKEN=$(python lockbox/generate_service_token.py --service-name github_public_behind_service_token --duration 300 --signing-key-file signing_key.txt --audience smoke_test)
curl -v localhost:8000/s/github_public_behind_service_token/orgs/google/repos -H "Authorization: Bearer $SERVICE_TOKEN"
echo
echo

echo "OK [GET/public/token]"
