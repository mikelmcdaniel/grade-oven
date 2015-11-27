#!/bin/bash
set -e  # exit on error

docker build -t grade_oven/grade_oven_base -f grade_oven_base.Dockerfile --rm --memory-swap=-1 .
docker build -t grade_oven/preheat_build -f preheat_build.Dockerfile --rm --memory-swap=-1 .
docker build -t grade_oven/bake_test -f bake_test.Dockerfile --rm --memory-swap=-1 .
docker build -t grade_oven/serve_web -f serve_web.Dockerfile --rm --memory-swap=-1 .
