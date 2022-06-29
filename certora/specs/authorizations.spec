methods {
	balanceOf(address) returns (uint256) envfree
}

rule transferPublicRole()
{
	env e;

	address user; address to; uint256 amount;
	uint256 balanceBefore = balanceOf(user);
	require (e.msg.sender == user);

    require (isCapabilityPublic(e, transfer(address, uint256).selector));

	transfer@withrevert(e, to, amount);

	assert (lastReverted <=> balanceBefore < amount);
}
