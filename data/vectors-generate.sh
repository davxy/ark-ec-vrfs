#!/usr/bin/env bash

cd "$(dirname "$0")"
mkdir -p vectors

cargo test \
  --release \
  --features full,test-vectors \
  -- \
  --nocapture \
  --ignored
