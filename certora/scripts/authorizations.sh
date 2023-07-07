#!/bin/sh

make -C certora munged

certoraRun \
    certora/munged/Token.sol \
    --packages solmate=lib/solmate/src \
    --verify Token:certora/specs/authorizations.spec \
    --optimistic_loop \
    --loop_iter 2 \
    --solc_args '["--optimize"]' \
    --smt_timeout 60 \
    --msg "authorizations" \
    --send_only \
    --prover_args "-useBitVectorTheory" \
    "$@"
