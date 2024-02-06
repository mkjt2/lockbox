#!/usr/env/bin bash

# Runs a demo server at https://lockbox-proxy-demo.fly.dev

fly apps create lockbox-proxy-demo || echo "Mayhaps app already exists?"

# Mount sample_config.json from current repo root
fly deploy -c fly.toml \
  --file-local=/etc/lockbox/config.json=../sample_config_with_secrets.json \
  --file-local=/etc/lockbox/signing_key.txt=../signing_key.txt \
  --ha=false \
  --image jjak82/lockbox-proxy:v0.1.3
