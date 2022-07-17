methods {
    totalSupply() returns(uint256) envfree
    balanceOf(address) returns(uint256) envfree
    allowance(address, address) returns(uint256) envfree
}

rule erc20TransferRevertConditions() {
    env e;
    address sender; address to; uint256 amount;
    require (sender == e.msg.sender);
    uint256 balanceBefore = balanceOf(sender);
    require (e.msg.value == 0); 

    transfer@withrevert(e, to, amount);

    assert (lastReverted <=> amount > balanceBefore);
}

rule erc20TransferFromRevertConditions() {
    env e;
    address sender; address from; address to; uint256 amount;
    require (sender == e.msg.sender);
    uint256 balanceBefore = balanceOf(from);
    uint256 allowanceBefore = allowance(from, sender);
    require (e.msg.value == 0);

    transferFrom@withrevert(e, from, to, amount);

    assert (lastReverted <=> amount > balanceBefore || amount > allowanceBefore);
}

rule erc20MintRevertConditions() {
    env e;
    address to; uint256 amount;
    uint256 totalSupply = totalSupply();
    require (e.msg.value == 0);

    mint@withrevert(e, to, amount);

    assert (lastReverted <=> totalSupply > max_uint256 - amount);
}
