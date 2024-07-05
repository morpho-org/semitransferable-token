methods {
    function totalSupply() external returns (uint256) envfree;
    function balanceOf(address) external returns (uint256) envfree;
    function allowance(address, address) external returns (uint256) envfree;
    function owner() external returns (address) envfree;
    function getUserRoles(address) external returns (bytes32) envfree;
    function isCapabilityPublic(bytes4) external returns (bool) envfree;
    function getRolesWithCapability(bytes4) external returns (bytes32) envfree;
    function doesUserHaveRole(address, uint8) external returns (bool) envfree;
    function doesRoleHaveCapability(uint8, bytes4) external returns (bool) envfree;
}


// AUTHORIZATION STORAGE

// The authorization variables are: owner, isCapabilityPublic, getUserRoles and getRolesCapability.

// owner variable

rule ownerChangingWithSetOwner(env e, method f, calldataarg args) {
    address ownerBefore = owner();

    f(e, args);

    address ownerAfter = owner();
    assert (ownerAfter != ownerBefore =>
            f.selector == sig:setOwner(address).selector);
}

rule setOwnerShouldSetOwner(env e, address newOwner) {
    setOwner(e, newOwner);

    address ownerAfter = owner();
    assert (ownerAfter == newOwner);
}

// isCapabilityPublic mapping

rule isCapabilityPublicChangingWithSetPublicCapability(env e, method f, calldataarg args) {
    bytes4 capability;
    bool capabilityPublicBefore = isCapabilityPublic(capability);

    f(e, args);

    bool capabilityPublicAfter = isCapabilityPublic(capability);
    assert (capabilityPublicAfter != capabilityPublicBefore =>
            f.selector == sig:setPublicCapability(bytes4, bool).selector);
}

rule setPublicCapabilityShouldSetIsPublicCapability(env e, bytes4 capability, bool enabled) {
    setPublicCapability(e, capability, enabled);

    bool capabilityIsPublicAfter = isCapabilityPublic(capability);
    assert (capabilityIsPublicAfter == enabled);
}

// getUserRoles mapping

rule getUserRolesChangingWithSetUserRole(env e, method f, calldataarg args, address user) {
    bytes32 userRolesBefore = getUserRoles(user);

    f(e, args);

    bytes32 userRolesAfter = getUserRoles(user);
    assert (userRolesAfter != userRolesBefore =>
            f.selector == sig:setUserRole(address, uint8, bool).selector);
}

rule setUserRoleShouldChangeDoesUserHaveRole(env e, address user, uint8 role, bool enabled) {
    setUserRole(e, user, role, enabled);

    bool userHasRoleAfter = doesUserHaveRole(user, role);
    assert (userHasRoleAfter == enabled);
}

rule doesUserHaveRoleChangingWithSetUserRole(env e, method f, calldataarg args) {
    address user; uint8 role;
    bool userHasRoleBefore = doesUserHaveRole(user, role);

    f(e, args);

    bool userHasRoleAfter = doesUserHaveRole(user, role);
    assert (userHasRoleAfter != userHasRoleBefore =>
            f.selector == sig:setUserRole(address, uint8, bool).selector);
}

rule doesUserHaveRoleChangingArgs(env e, address userChanged, uint8 roleChanged, bool enabledChanged) {
    address user; uint8 role;
    bool userHasRoleBefore = doesUserHaveRole(user, role);

    setUserRole(e, userChanged, roleChanged, enabledChanged);

    bool userHasRoleAfter = doesUserHaveRole(user, role);
    assert (userHasRoleAfter != userHasRoleBefore =>
            userChanged == user && roleChanged == role && userHasRoleAfter == enabledChanged);
}

// getRolesWithCapability mapping

rule getRolesWithCapabilityChangingWithSetRoleCapability(env e, method f, calldataarg args) {
    bytes4 capability;
    bytes32 rolesBefore = getRolesWithCapability(capability);

    f(e, args);

    bytes32 rolesAfter = getRolesWithCapability(capability);
    assert (rolesAfter != rolesBefore =>
            f.selector == sig:setRoleCapability(uint8, bytes4, bool).selector);
}

rule setRoleCapabilityShouldChangeDoesRoleHaveCapability(env e, uint8 role, bytes4 capability, bool enabled) {
    setRoleCapability(e, role, capability, enabled);

    bool roleHasCapabilityAfter = doesRoleHaveCapability(role, capability);
    assert (roleHasCapabilityAfter == enabled);
}

rule doesRoleHaveCapabilityChangingWithSetRoleCapability(env e, method f, calldataarg args, uint8 role) {
    bytes4 capability;
    bool roleHasCapabilityBefore = doesRoleHaveCapability(role, capability);

    f(e, args);

    bool roleHasCapabilityAfter = doesRoleHaveCapability(role, capability);
    assert (roleHasCapabilityAfter != roleHasCapabilityBefore =>
            f.selector == sig:setRoleCapability(uint8, bytes4, bool).selector);
}

rule doesRoleHaveCapabilityChangingArgs(uint8 roleChanged, bytes4 capabilityChanged, bool enabledChanged) {
    env e;
    uint8 role; bytes4 capability;
    bool roleHasCapabilityBefore = doesRoleHaveCapability(role, capability);

    setRoleCapability(e, roleChanged, capabilityChanged, enabledChanged);

    bool roleHasCapabilityAfter = doesRoleHaveCapability(role, capability);
    assert (roleHasCapabilityAfter != roleHasCapabilityBefore =>
            roleChanged == role && capabilityChanged == capability && roleHasCapabilityAfter == enabledChanged);
}


// AUTHORIZATION FUNCTIONS

// Compute the set of all the functions that need authorization: setOwner, setPublicCapability, setUserRole, setRoleCapability, transfer, transferFrom, mint
// We first check that if a function requires authorization then it belongs to the previous set.
rule allFunctionsNeedingAuthorization() {
    env e;
    storage initialState = lastStorage;
    method f; calldataarg args;

    f@withrevert(e, args);
    bool revertNormal = lastReverted;

    env e_auth; bool enabled;
    setPublicCapability(e_auth, to_bytes4(f.selector), enabled) at initialState;
    f@withrevert(e, args);
    bool revertOwner = lastReverted;

    assert ((revertOwner != revertNormal) =>
            (f.selector == sig:setOwner(address).selector) ||
             f.selector == sig:setPublicCapability(bytes4, bool).selector ||
             f.selector == sig:setUserRole(address, uint8, bool).selector ||
             f.selector == sig:setRoleCapability(uint8, bytes4, bool).selector ||
             f.selector == sig:transfer(address, uint256).selector ||
             f.selector == sig:transferFrom(address, address, uint256).selector ||
             f.selector == sig:mint(address, uint256).selector);
}

// Check that those functions indeed require authorization.

definition noRoleUnauthorizedUserForCapability(address user, bytes4 capability) returns bool =
    getUserRoles(user) == to_bytes32(0) &&
    user != owner() &&
    ! isCapabilityPublic(capability);


rule setOwnerRequiresAuthorization(env e, address newOwner) {
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:setOwner(address).selector));

    setOwner@withrevert(e, newOwner);

    assert lastReverted;
}

rule setPublicCapabilityRequiresAuthorization(env e, bytes4 capability, bool enabled) {
    uint8 roleAuth;
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:setPublicCapability(bytes4, bool).selector));

    setPublicCapability@withrevert(e, capability, enabled);

    assert lastReverted;
}

rule setUserRoleRequiresAuthorization(env e, address user, uint8 role, bool enabled) {
    uint8 roleAuth;
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:setUserRole(address, uint8, bool).selector));

    setUserRole@withrevert(e, user, role, enabled);

    assert lastReverted;
}

rule setRoleCapabilityRequiresAuthorization(env e, uint8 role, bytes4 capability, bool enabled) {
    uint8 roleAuth;
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:setRoleCapability(uint8, bytes4, bool).selector));

    setRoleCapability@withrevert(e, role, capability, enabled);

    assert lastReverted;
}

rule transferRequiresAuthorization(env e, address to, uint256 amount) {
    uint8 roleAuth;
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:transfer(address, uint256).selector));

    transfer@withrevert(e, to, amount);

    assert lastReverted;
}

rule transferFromRequiresAuthorization(env e, address from, address to, uint256 amount) {
    uint8 roleAuth;
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:transferFrom(address, address, uint256).selector));

    transferFrom@withrevert(e, from, to, amount);

    assert lastReverted;
}

rule mintRequiresAuthorization(env e, address to, uint256 amount) {
    uint8 roleAuth;
    require noRoleUnauthorizedUserForCapability(e.msg.sender, to_bytes4(sig:mint(address, uint256).selector));

    mint@withrevert(e, to, amount);

    assert lastReverted;
}

// Compute the set of all functions able to change the authorizations.
// This rule can't be checked for now by the Certora tool because there is no way to discriminate on the revert reason. Thus it can fail because the underlying functions reverts.
// rule allAuthorizationFunctions() {
//     env e_auth; env e;
//     storage initialState = lastStorage;
//     method authFunction; calldataarg argsAuth;
//     method f; calldataarg args;

//     f@withrevert(e, args);
//     bool revertWithoutAuth = lastReverted; // would need to be able to check if the revert reason is "UNAUTHORIZED".

//     authFunction(e_auth, argsAuth) at initialState;
//     f@withrevert(e, args);
//     bool revertWithAuth = lastReverted; // would need to be able to check if the revert reason is "UNAUTHORIZED".

//     assert ((revertWithAuth != revertWithoutAuth) =>
//             (authFunction.selector == sig:setOwner(address).selector) ||
//              authFunction.selector == sig:setPublicCapability(bytes4, bool).selector ||
//              authFunction.selector == sig:setUserRole(address, uint8, bool).selector ||
//              authFunction.selector == sig:setRoleCapability(uint8, bytes4, bool).selector));
// }


// AUTHORIZATION CONDITIONS

definition userIsRoleAuthorizedForCapability(address user, uint8 role, bytes4 capability) returns bool =
    user == owner() ||
    isCapabilityPublic(capability) ||
    doesUserHaveRole(user, role) && doesRoleHaveCapability(role, capability);

rule transferRevertingConditions(env e, address to, uint256 amount) {
    uint8 role;
    require (e.msg.value == 0);
    require userIsRoleAuthorizedForCapability(e.msg.sender, role, to_bytes4(sig:transfer(address, uint256).selector));

    storage initialState = lastStorage;
    underlyingTransfer@withrevert(e, to, amount);
    bool revertAfterUnderlyingTransfer = lastReverted;

    transfer@withrevert(e, to, amount) at initialState;
    bool revertAfterTransfer = lastReverted;

    assert (revertAfterTransfer <=> revertAfterUnderlyingTransfer);
}

rule transferFromRevertingConditions(env e, address from, address to, uint256 amount) {
    uint8 role;
    require (e.msg.value == 0);
    require userIsRoleAuthorizedForCapability(e.msg.sender, role, to_bytes4(sig:transferFrom(address, address, uint256).selector));

    storage initialState = lastStorage;
    underlyingTransferFrom@withrevert(e, from, to, amount);
    bool revertAfterUnderlyingTransferFrom = lastReverted;

    transferFrom@withrevert(e, from, to, amount) at initialState;
    bool revertAfterTransferFrom = lastReverted;

    assert (revertAfterTransferFrom <=> revertAfterUnderlyingTransferFrom);
}

rule mintRevertingConditions(env e, address to, uint256 amount) {
    uint8 role;
    require (e.msg.value == 0);
    require userIsRoleAuthorizedForCapability(e.msg.sender, role, to_bytes4(sig:mint(address, uint256).selector));

    storage initialState = lastStorage;
    underlyingMint@withrevert(e, to, amount);
    bool revertAfterUnderlyingMint = lastReverted;

    mint@withrevert(e, to, amount) at initialState;
    bool revertAfterMint = lastReverted;

    assert (revertAfterMint <=> revertAfterUnderlyingMint);
}
