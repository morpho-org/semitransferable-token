#!/bin/sh

make -C certora munged

certoraRun \
    certora/ERC20Stripped.sol \
    --packages solmate=lib/solmate/src/ \
    --verify ERC20Stripped:certora/specs/erc20reverts.spec \
    --loop_iter 2 \
    --solc_args '["--optimize"]' \
    --settings -t=60 \
    --msg "erc20 reverts" \
    --send_only \
    $@
