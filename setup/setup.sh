#!/bin/bash
set -e  # exit on error

docker build -t grade_oven/grade_oven -f grade_oven.Dockerfile --rm --memory-swap=-1 .
