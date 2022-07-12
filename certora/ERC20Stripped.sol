// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.13;

// This file is used to compare the revert conditions between a "stripped" version of an ERC20 and a semitransferable version.

import {ERC20} from "solmate/tokens/ERC20.sol";

contract ERC20Stripped is ERC20 {
    constructor(
      string memory _name,
      string memory _symbol,
      uint8 _decimals,
      address _owner
    ) ERC20(_name, _symbol, _decimals) {}
}
