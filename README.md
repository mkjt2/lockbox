# Lockbox

Lockbox is a forward proxy for making third party API calls.

# Why?

Automation or workflow platforms like [Zapier](https://zapier.com) and [IFTTT](https://ifttt.com) allow
"webhook" actions for interacting with third party APIs.

* [IFTTT webhooks](https://ifttt.com/maker_webhooks)
* [Zapier webhooks](https://zapier.com/apps/webhook/integrations)

They require you to provide your API keys to them in order to access third party APIs on your behalf.

<!-- TODO validate how this works with Zapier x Slack - might need alternate example -->
<!-- TODO add a diagram -->

This is a security risk. You are trusting them to keep your API keys safe, and that they do not misuse them.

# How Lockbox helps

You run your own Lockbox server.

When a workflow platform needs to make a third party API call on your behalf, it makes an Lockbox API call instead.
Lockbox makes the call to the third party API, and returns the result to the workflow platform.

<!-- TODO add a diagram -->

## Main benefits

* Third party API keys are never exposed to the workflow platform
* You can audit all API calls made on your behalf
* You can restrict access to external APIs in a more fine grained manner
* Rate limit third party API calls

## Drawbacks

* You need to run an instance of Lockbox on your own infrastructure. You own its performance, security and reliability.
* Centralization of YOUR API credentials (with your Lockbox instance). However, consider this a different kind of
  centralization. I.e. Workflow automation platforms centralize credentials for a large number of users in a single
  system too, possibly presenting a valuable aggregate target for attackers.

# How to run Lockbox

## Prepare a services config file

May be call it `sample_config.json`. Example:

```json5
{
  "services": {
    // Access GitHub APIs that do not require auth
    "github_public": {
      "base_url": "api.github.com",
      "requires_service_token": false
    },
    // Access GitHub APIs that do not require auth - except Lockbox requires auth (by "service token')
    "github_public_behind_service_token": {
      "base_url": "api.github.com",
      "requires_service_token": true
    },
  }
}
```

## Choose a Lockbox secret key

This secret key is used to generate signed service tokens. Service tokens are used to authenticate API calls to Lockbox.

```bash
echo "YOUR_SUPER_SECRET_VALUE" > signing_key.txt
```

## Run Lockbox server

This snippet runs Lockbox server on `localhost:8000`. It uses [poetry](https://python-poetry.org/) for Python dependency
management.

```bash

git clone https://github.com/mkjt2/lockbox.git
cd lockbox

export LOCKBOX_SIGNING_KEY_FILE=signing_key.txt
export LOCKBOX_CONFIG_PATH=sample_config.json

poetry run gunicorn lockbox.app:app --preload
```

# Accessing third-party APIs via Lockbox

Example: Call to GitHub API to list Google's public repos.

*Without Lockbox*, the request would have been `GET https://api.github.com/orgs/google/repos`

## Configure `api.github.com` in service config file.

See example [above](#prepare-a-services-config-file).

## Generate a Lockbox service token

Each Lockbox service token allows access to a single service (e.g. `github_public_behind_service_token`).

This command generates a Lockbox service token that authorizes the bearer to access GitHub API through Doorman.

The service token is saved to the `SERVICE_TOKEN` environment variable.

```bash
export SERVICE_TOKEN=$(python lockbox/generate_service_token.py \
    --service-name github_public_behind_service_token \
    --signing-key-file signing_key.txt \
    --audience walkthrough
    )
```

Note: `audience` identifies the intended recipient of the service token.

## Make the Lockbox API call

```bash
# Lockbox URL structure: /s/{service_name}/{path}
curl localhost:8000/s/github_with_auth/orgs/google/repos -v -H "Authorization: Bearer $SERVICE_TOKEN"
```

## How to revoke service tokens

Revocation is done through checking the `audience` claim of the service token.

In the service config file (e.g. `sample_config.json`), each service may specify a list of `audiences` that are valid:

```json5
{
  "services": {

    // Access GitHub APIs that DO require auth - and Lockbox requires auth (by "service token") to protect access to that.
    // Additionally, only service tokens with audience "zapier_webhook" will be accepted by Lockbox.
    "github_private_behind_service_token": {
      // ...
      // ...
      "requires_service_token": true,
      "valid_audiences": [
        "walkthrough"
      ]
    },
  }
}
```

* If `valid_audiences` is unset, or set to `null`, it means all audiences are valid.
* If `valid_audiences` is set to a list, then only audiences in the list are valid.

In the example above, only service tokens with audience `walkthrough` is valid for the service
`github_private_behind_service_token`.

To revoke ALL service tokens for a service, set `valid_audiences` to `[]`.

Note `sample_config.json` updates are not automatically reloaded. You need to restart Lockbox server for changes to take.
