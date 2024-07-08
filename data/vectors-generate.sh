#!/usr/bin/env bash

cargo test \
  --release \
  --features full \
  -- \
  --ignored
