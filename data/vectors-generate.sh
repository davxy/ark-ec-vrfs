#!/usr/bin/env bash

cargo test \
  --release \
  --features full,test-vectors \
  -- \
  --nocapture \
  --ignored
