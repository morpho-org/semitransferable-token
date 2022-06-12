// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.13;

import "src/Token.sol";
import "forge-std/Script.sol";

contract Deploy is Script {

  string constant name = "My Token";
  string constant symbol = "TKN";
  address constant owner = address(0x0);

  function run() external {
    vm.startBroadcast();
    Token token = new Token({
      _name: name,
      _symbol: symbol,
      _decimals: 18,
      _owner: msg.sender
    });
    token.setRoleCapability(0,address(token),Token.transfer.selector,true);
    token.setRoleCapability(0,address(token),Token.transferFrom.selector,true);
    token.setRoleCapability(1,address(token),Token.mint.selector,true);

    token.setOwner(owner);
    vm.stopBroadcast();

  }
}
