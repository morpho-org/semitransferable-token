// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "src/Token.sol";

contract Owner {
  Token token;
  function setToken(Token _token) external {
    token = _token;
  }
  /* ERC20 control functions */
  function mint(address to, uint amount) external {
    token.mint(to, amount);
  }
  function mint(uint amount) external {
    token.mint(address(this), amount);
  }
  function approve(address spender) external {
    token.approve(spender, type(uint256).max);
  }
  function transfer(address to, uint256 amount) external {
    token.transfer(to, amount);
  }
  function transferFrom(address from, address to, uint256 amount) external {
    token.transferFrom(from, to, amount);
  }

  /* RolesAuthority control functions */
  // target omitted from arguments since it's always the token
  function setRoleCapability(
    uint8 role,
    bytes4 functionSig,
    bool enabled
  ) external {
    token.setRoleCapability(role,address(token),functionSig,enabled);
  }

  function setUserRole(
    address user,
    uint8 role,
    bool enabled) external {
      token.setUserRole(user,role,enabled);
  }

  // target omitted from arguments since it's always the token
  function setPublicCapability(
    bytes4 functionSig,
    bool enabled
  ) external {
    token.setPublicCapability(address(token),functionSig,enabled);
  }

  function disown() external {
    token.setOwner(address(0));
  }

}

contract TokenTest is Test {
  Token token;
  Owner owner;
  address $owner;
  address $this;

  uint8 immutable TRANSFER_ROLE = 0;
  uint8 immutable MINT_ROLE = 1;

  // tests expect initial balances to be zero
  function setUp() public {
    $this = address(this);

    owner = new Owner();
    $owner = address(owner);

    token = new Token("Token","TK",18,$owner);

    owner.setToken(token);

    owner.setRoleCapability(TRANSFER_ROLE,Token.transfer.selector,true);
    owner.setRoleCapability(TRANSFER_ROLE,Token.transferFrom.selector,true);
    owner.setRoleCapability(MINT_ROLE,Token.mint.selector,true);
  }

  /* Test basic parameters */

  function testBasicParameterSettings() public {
    assertEq(token.name(),"Token","name");
    assertEq(token.symbol(),"TK","symbol");
    assertEq(token.decimals(),18,"decimals");
    assertEq(token.owner(),$owner,"owner");
  }

  /* Test `transfer` */

  function testNoTransferByDefault(uint amount) public {
    owner.mint($this,amount);
    vm.expectRevert("UNAUTHORIZED");
    token.transfer($owner,amount);
  }

  function testTransferReturn() public {
    owner.mint($this,1);
    owner.setUserRole($this,TRANSFER_ROLE,true);
    assertEq(token.transfer($owner,1),true);
  }

  function testTransferOK1(uint amount) public {
    owner.mint(amount);
    owner.transfer($this, amount);
    assertEq(token.balanceOf($this),amount);
  }
  function testTransferOK2(uint amount) public {
    owner.setUserRole($this,TRANSFER_ROLE,true);
    owner.mint($this,amount);
    token.transfer($owner,amount);
    assertEq(token.balanceOf($owner),amount);
  }

  function testTransferOK3(uint amount) public {
    owner.setPublicCapability(Token.transfer.selector,true);
    owner.mint($this, amount);
    token.transfer($owner, amount);
    assertEq(token.balanceOf($owner),amount);
  }

  /* Test `transferFrom` */

  function testNoTransferFromByDefault(uint amount) public {
    owner.mint($this,amount);
    owner.approve($this);
    vm.expectRevert("UNAUTHORIZED");
    token.transferFrom($owner,$this,amount);
  }

  function testTransferFromReturn() public {
    owner.mint(1);
    owner.approve($this);
    owner.setUserRole($this,TRANSFER_ROLE,true);
    assertEq(token.transferFrom($owner,$this,1),true);
  }

  function testTransferFromOK1(uint amount) public {
    token.approve($owner,type(uint).max);
    owner.mint($this, amount);
    owner.transferFrom($this, $owner, amount);
    assertEq(token.balanceOf($owner),amount);
  }
  function testTransferFromOK2(uint amount) public {
    owner.approve($this);
    owner.setUserRole($this,TRANSFER_ROLE,true);
    owner.mint(amount);
    token.transferFrom($owner,$this,amount);
    assertEq(token.balanceOf($this),amount);
  }

  function testTransferFromOK3(uint amount) public {
    owner.approve($this);
    owner.setPublicCapability(Token.transferFrom.selector,true);
    owner.mint($owner, amount);
    token.transferFrom($owner, $this, amount);
    assertEq(token.balanceOf($this),amount);
  }

  /* Test `mint` */

  function testNoMintByDefault(uint amount) public {
    vm.expectRevert("UNAUTHORIZED");
    token.mint($this, amount);
  }

  function testMintOK1(uint amount) public {
    owner.mint($owner,amount);
    assertEq(token.balanceOf($owner),amount);
  }
  function testMintOK2(uint amount) public {
    owner.setUserRole($this,MINT_ROLE,true);
    token.mint($this,amount);
    assertEq(token.balanceOf($this),amount);
  }

  /* Test `burn` */

  function testSelfBurnOK(uint amount) public {
    owner.mint($this,amount);
    token.burn(amount/2);
    assertEq(token.balanceOf($this),amount/2 + amount%2);
  }

  function testSelfBurnKO(uint amount) public {
    owner.mint($this,amount);
    vm.expectRevert(stdError.arithmeticError);
    token.burn(amount+1);
  }
  /* Test that removing owner works */

  function testRemoveOwner(uint amount) public {
    owner.disown();
    vm.expectRevert("UNAUTHORIZED");
    owner.mint($this,amount);
  }
}
