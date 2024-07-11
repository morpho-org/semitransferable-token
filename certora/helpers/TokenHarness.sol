// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.13;

import {Token} from "../../src/Token.sol";

/// @dev Harness contract for formal verification purposes only.
/// @dev Add underlying functions to the public interface to be able to compare them with the actual functions.
contract TokenHarness is Token {
  constructor(
    string memory _name,
    string memory _symbol,
    uint8 _decimals,
    address _owner
  ) Token(_name, _symbol, _decimals, _owner) {}

  /// @dev Copy underlying transfer code.
  function underlyingTransfer(
    address to,
    uint256 amount
  ) public returns (bool) {
    balanceOf[msg.sender] -= amount;

    // Cannot overflow because the sum of all user
    // balances can't exceed the max uint256 value.
    unchecked {
      balanceOf[to] += amount;
    }

    emit Transfer(msg.sender, to, amount);

    return true;
  }

  /// @dev Copy underlying transferFrom code.
  function underlyingTransferFrom(
    address from,
    address to,
    uint256 amount
  ) public returns (bool) {
    uint256 allowed = allowance[from][msg.sender]; // Saves gas for limited approvals.

    if (allowed != type(uint256).max)
      allowance[from][msg.sender] = allowed - amount;

    balanceOf[from] -= amount;

    // Cannot overflow because the sum of all user
    // balances can't exceed the max uint256 value.
    unchecked {
      balanceOf[to] += amount;
    }

    emit Transfer(from, to, amount);

    return true;
  }

  function underlyingMint(address to, uint256 amount) public {
    _mint(to, amount);
  }

  function underlyingBurn(uint256 amount) public {
    _burn(msg.sender, amount);
  }
}
