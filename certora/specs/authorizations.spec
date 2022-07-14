methods {
    totalSupply() returns (uint256) envfree
    allowance(address, address) returns (uint256) envfree
    owner() returns (address) envfree
	balanceOf(address) returns (uint256) envfree
    getUserRoles(address) returns (uint256) envfree
    doesUserHaveRole(address, uint8) returns (bool) envfree
    isCapabilityPublic(uint32) returns (bool) envfree
    getRolesWithCapability(uint32) returns (uint256) envfree
    doesRoleHaveCapability(uint8, uint32) returns (bool) envfree
}

// The following functions are called the authorization functions:
// setOwner, setPublicCapability, setUserRole and setRoleCapability


// AUTHORIZATION OVERVIEW

// Check that only the authorization functions are able to change the authorization storage.

rule ownerChanging() {
    env e;
    method f; calldataarg args; uint32 newOwner;
    uint256 ownerBefore = owner();

    f(e, args);

    uint256 ownerAfter = owner();
    assert (ownerAfter != ownerBefore =>
            f.selector == setOwner(address).selector);
}

rule isCapabilityPublicChanging() {
    env e;
    method f; calldataarg args; uint32 capability;
    bool capabilityPublicBefore = isCapabilityPublic(capability);

    f(e, args);

    bool capabilityPublicAfter = isCapabilityPublic(capability);
    assert (capabilityPublicAfter != capabilityPublicBefore =>
            f.selector == setPublicCapability(uint32, bool).selector);
}

rule getUserRolesChanging() {
    env e;
    method f; calldataarg args; address user;
    uint256 userRolesBefore = getUserRoles(user);

    f(e, args);

    uint userRolesAfter = getUserRoles(user);
    assert (userRolesAfter != userRolesBefore =>
            f.selector == setUserRole(address, uint8, bool).selector);
}

rule doesUserHaveRoleChangingMethod() {
    env e;
    method f; calldataarg args; address user; uint8 role;
    bool userHasRoleBefore = doesUserHaveRole(user, role);

    f(e, args);

    bool userHasRoleAfter = doesUserHaveRole(user, role);
    assert (userHasRoleAfter != userHasRoleBefore =>
            f.selector == setUserRole(address, uint8, bool).selector
            // TODO: is there a way to check the following ?
            // && args == (user, role, )
             );
}

rule doesUserHaveRoleChangingArgs() {
    env e;
    address userChanged; uint8 roleChanged; bool enabledChanged;
    address user; uint8 role;
    bool userHasRoleBefore = doesUserHaveRole(user, role);

    setUserRole(e, userChanged, roleChanged, enabledChanged);

    bool userHasRoleAfter = doesUserHaveRole(user, role);
    assert (userHasRoleAfter != userHasRoleBefore =>
            userChanged == user && roleChanged == role);
}

rule getRolesWithCapabilityChanging() {
    env e;
    method f; calldataarg args; uint32 capability;
    uint256 rolesBefore = getRolesWithCapability(capability);

    f(e, args);

    uint256 rolesAfter = getRolesWithCapability(capability);
    assert (rolesAfter != rolesBefore =>
            f.selector == setRoleCapability(uint8, uint32, bool).selector);
}

rule doesRoleHaveCapabilityChangingMethod() {
    env e;
    method f; calldataarg args; uint8 role; uint32 capability;
    bool roleHasCapabilityBefore = doesRoleHaveCapability(role, capability);

    f(e, args);

    bool roleHasCapabilityAfter = doesRoleHaveCapability(role, capability);
    assert (roleHasCapabilityBefore != roleHasCapabilityBefore =>
            f.selector == setRoleCapability(uint8, uint32, bool).selector);
}

rule doesRoleHaveCapabilityChangingArgs() {
    env e;
    uint8 roleChanged; uint32 capabilityChanged; bool enabledChanged; uint8 role; uint32 capability;
    bool roleHasCapabilityBefore = doesRoleHaveCapability(role, capability);

    setRoleCapability(e, roleChanged, capabilityChanged, enabledChanged);

    bool roleHasCapabilityAfter = doesRoleHaveCapability(role, capability);
    assert (roleHasCapabilityBefore != roleHasCapabilityBefore =>
            roleChanged == role && capabilityChanged == capability);
}

// Check that the authorization functions are able to change the authorization storage.

rule setPublicCapabilityShouldChangeIsPublicCapability() {
    env e;
    method f; bool enabled;

    setPublicCapability(e, f.selector, enabled);

    bool capabilityIsPublicAfter = isCapabilityPublic(f.selector);
    assert (capabilityIsPublicAfter == enabled);
}

rule setUserRoleShouldChangeDoesUserHaveRole() {
    env e;
    address user; uint8 role; bool enabled;

    setUserRole(e, user, role, enabled);

    bool userHasRoleAfter = doesUserHaveRole(user, role);
    assert (userHasRoleAfter == enabled);
}

rule setRoleCapabilityShouldChangeDoesRoleHaveCapability() {
    env e;
    uint8 role; method f; bool enabled;

    setRoleCapability(e, role, f.selector, enabled);

    bool roleHasCapabilityAfter = doesRoleHaveCapability(role, f.selector);
    assert (roleHasCapabilityAfter == enabled);
}

// Check that the functions able to change the function authorizations are the authorization functions.
// TODO: exclude underlying functions constraints (in terms of tokens essentially).
rule allFunctionsChangingAuthorization() {
    env e_auth; env e;
    storage initialState = lastStorage;
    method authFunction; calldataarg argsAuth;
    method f; calldataarg args;

    f@withrevert(e, args);
    bool revertWithoutAuth = lastReverted;

    authFunction(e_auth, argsAuth) at initialState;
    f@withrevert(e, args);
    bool revertWithAuth = lastReverted;

    assert ((revertWithAuth != revertWithoutAuth) =>
            (authFunction.selector == setOwner(address).selector) ||
             authFunction.selector == setPublicCapability(uint32, bool).selector ||
             authFunction.selector == setUserRole(address, uint8, bool).selector ||
             authFunction.selector == setRoleCapability(uint8, uint32, bool).selector);
}


// OWNER AUTHORIZATION

// Check that the owner is always authorized. 
// See erc20reverts.spec to compare to the underlying function revert conditions.

rule ownerCanAlwaysTransfer() {
    env e;
    address sender; address to; uint256 amount;
    require (sender == e.msg.sender);
    require (sender == owner());
    uint256 balanceBefore = balanceOf(sender);
    require (e.msg.value == 0);

    transfer@withrevert(e, to, amount);

    assert (lastReverted <=> amount > balanceBefore);
}

rule ownerCanAlwaysTransferFrom() {
    env e;
	address sender; address from; address to; uint256 amount;
    require (sender == e.msg.sender);
    require (sender == owner());
	uint256 balanceBefore = balanceOf(from);
    uint256 allowanceBefore = allowance(from, sender);
    require (e.msg.value == 0);

	transferFrom@withrevert(e, from, to, amount);

	assert (lastReverted <=> amount > balanceBefore || amount > allowanceBefore);
}

rule ownerCanAlwaysMint() {
	env e;
	address sender; address to; uint256 amount;
    require (sender == e.msg.sender);
    require (sender == owner());
    uint256 totalSupply = totalSupply();
    require (e.msg.value == 0);

	mint@withrevert(e, to, amount);

	assert (lastReverted <=> totalSupply > max_uint256 - amount);
}


// PUBLIC AUTHORIZATION

// Check that public functions (as defined in RolesAuthority) are authorized.
// See erc20reverts.spec to compare to the underlying function revert conditions.

rule transferIsAuthorizedWhenPublicCapability() {
	env e;
	address sender; address to; uint256 amount;
    require (sender == e.msg.sender);
	uint256 balanceBefore = balanceOf(sender);
    require (e.msg.value == 0);

    require (isCapabilityPublic(transfer(address, uint256).selector));

	transfer@withrevert(e, to, amount);

	assert (lastReverted <=> amount > balanceBefore);
}

rule transferFromIsAuthorizedWhenPublicCapability() {
    env e;
	address sender; address from; address to; uint256 amount;
    require (sender == e.msg.sender);
	uint256 balanceBefore = balanceOf(from);
    uint256 allowanceBefore = allowance(from, sender);
    require (e.msg.value == 0);

    require (isCapabilityPublic(transferFrom(address, address, uint256).selector));

	transferFrom@withrevert(e, from, to, amount);

	assert (lastReverted <=> amount > balanceBefore || amount > allowanceBefore);
}

rule mintIsAuthorizedWhenPublicCapability() {
	env e;
	address sender; address to; uint256 amount;
    require (sender == e.msg.sender);
    uint256 totalSupply = totalSupply();
    require (e.msg.value == 0);

    require (isCapabilityPublic(mint(address, uint256).selector));

	mint@withrevert(e, to, amount);

	assert (lastReverted <=> totalSupply > max_uint256 - amount);
}


// ROLE AUTHORIZATION

// Check that users that have a role that has a capability for a function can call this function.
// See erc20reverts.spec to compare to the underlying function revert conditions.

rule transferIsAuthorizedWhenUserHasAppropriateRole() {
	env e;
	address sender; address to; uint256 amount; uint8 role;
    require (sender == e.msg.sender);
	uint256 balanceBefore = balanceOf(sender);
    require (e.msg.value == 0);

    require (doesUserHaveRole(sender, role));
    require (doesRoleHaveCapability(role, transfer(address, uint256).selector));

	transfer@withrevert(e, to, amount);

	assert (lastReverted <=> amount > balanceBefore);
}

rule transferFromIsAuthorizedWhenUserHasAppropriateRole() {
    env e;
	address sender; address from; address to; uint256 amount; uint8 role;
    require (sender == e.msg.sender);
	uint256 balanceBefore = balanceOf(from);
    uint256 allowanceBefore = allowance(from, sender);
    require (e.msg.value == 0);

    require (doesUserHaveRole(sender, role));
    require (doesRoleHaveCapability(role, transferFrom(address, address, uint256).selector));

	transferFrom@withrevert(e, from, to, amount);

	assert (lastReverted <=> amount > balanceBefore || amount > allowanceBefore);
}

rule mintIsAuthorizedWhenUserHasAppropriateRole() {
	env e;
	address sender; address to; uint256 amount; uint8 role;
    require (sender == e.msg.sender);
    uint256 totalSupply = totalSupply();
    require (e.msg.value == 0);

    require (doesUserHaveRole(sender, role));
    require (doesRoleHaveCapability(role, mint(address, uint256).selector));

	mint@withrevert(e, to, amount);

	assert (lastReverted <=> totalSupply > max_uint256 - amount);
}
