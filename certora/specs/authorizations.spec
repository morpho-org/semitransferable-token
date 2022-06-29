methods {
	balanceOf(address) returns (uint256) envfree
}

// TODO: make sure that the revert conditions are the same for the underlying token.

rule transferIsAuthorizedWhenPublicCapability() {
	env e;
	address sender; address to; uint256 amount;
    require(sender == e.msg.sender);
	uint256 balanceBefore = balanceOf(sender);
    // require (e.msg.value == 0); 
    // why is this not needed ?
    // - test without next line too
    // - add it to other rules ?

    require (isCapabilityPublic(e, transfer(address, uint256).selector));

	transfer@withrevert(e, to, amount);

	assert (lastReverted <=> amount > balanceBefore);
}

rule transferFromIsAuthorizedWhenPublicCapability() {
    env e;
	address sender; address from; address to; uint256 amount;
    require(sender == e.msg.sender);
	uint256 balanceBefore = balanceOf(from);
    uint256 allowanceBefore = allowance(e, from, sender);

    require (isCapabilityPublic(e, transferFrom(address, address, uint256).selector));

	transferFrom@withrevert(e, from, to, amount);

	assert (lastReverted <=> amount > balanceBefore || amount > allowanceBefore);
}

rule mintIsAuthorizedWhenPublicCapability() {
	env e;
	address sender; address to; uint256 amount;
    require(sender == e.msg.sender);
    uint256 totalSupply = totalSupply(e);

    require (isCapabilityPublic(e, mint(address, uint256).selector));

	mint@withrevert(e, to, amount);

	assert (lastReverted <=> totalSupply > max_uint256 - amount);
}
