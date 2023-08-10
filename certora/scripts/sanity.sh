#!/bin/sh

make -C certora munged

certoraRun \
    certora/munged/Token.sol \
    --packages solmate=lib/solmate/src/ \
    --verify Token:certora/specs/sanity.spec \
    --loop_iter 2 \
    --solc_args '["--optimize"]' \
    --settings -t=60 \
    --msg "sanity" \
    "$@"
