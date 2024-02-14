#!/usr/bin/env bash

set -ue

LOCKBOX_VERSION=0.1.3
IMAGE_NAME=jjak82/lockbox-proxy

# This tags and uploads an image to Docker Hub
docker build -t "$IMAGE_NAME:latest" -t "$IMAGE_NAME:$LOCKBOX_VERSION" --platform linux/amd64 --platform linux/arm64 .

docker push "$IMAGE_NAME:$LOCKBOX_VERSION"
docker push "$IMAGE_NAME:latest"
