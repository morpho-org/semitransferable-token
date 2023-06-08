#!/bin/sh

make -C certora munged

certoraRun \
    certora/munged/Token.sol \
    certora/helpers/Utils.sol \
    --packages solmate=lib/solmate/src \
    --verify Token:certora/specs/authorizations.spec \
    --optimistic_loop \
    --loop_iter 2 \
    --solc_args '["--optimize"]' \
    --settings -t=60 \
    --msg "authorizations" \
    --send_only \
    --settings -useBitVectorTheory \
    $@
