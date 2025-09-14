// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // 💡 EFFECTS: Set balance to 0 BEFORE the external call
        balances[msg.sender] = 0;

        // 💡 INTERACTIONS: External call after state changes
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
    }

    // Helper to check balance
    function getBalance() external view returns (uint) {
        return balances[msg.sender];
    }
}
