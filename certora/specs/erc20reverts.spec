methods {
    balanceOf(address) returns(uint256) envfree
    _mint(address, uint256) envfree
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
    uint256 allowanceBefore = allowance(e, from, sender);

	transferFrom@withrevert(e, from, to, amount);

	assert (lastReverted <=> amount > balanceBefore || amount > allowanceBefore);
}

// Why is this rule skipped ?
rule erc20MintRevertConditions() {
	env e;
	address sender; address to; uint256 amount;
    require (sender == e.msg.sender);
    uint256 totalSupply = totalSupply(e);

	_mint@withrevert(to, amount);

	assert (lastReverted <=> totalSupply > max_uint256 - amount);
}
