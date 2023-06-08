
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

contract Utils {
    function toBytes4(uint32 x) public pure returns (bytes4) {
        return bytes4(x);
    }
}
