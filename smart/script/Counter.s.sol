// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/SimpleChannelManager.sol";

contract DeploySimpleStorage is Script {
    uint256 public constant NUM_ACCOUNTS = 30;
    uint256 public constant DEPOSIT_AMOUNT = 50 ether;

    function run() external {
        // --- 1. DEPLOY THE CONTRACT ---
        // Get the private key of the deployer from the environment
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        vm.startBroadcast(deployerPrivateKey);
        PacketChain packetchain = new PacketChain();
        vm.stopBroadcast();

        console.log("PacketChain deployed at:", address(packetchain));

        // --- 2. FUND THE DEPLOYED CONTRACT FROM 30 ACCOUNTS ---
        string memory mnemonic = "test test test test test test test test test test test junk";
        if (bytes(mnemonic).length == 0) {
            revert("MNEMONIC environment variable not set!");
        }

        console.log("\nStarting deposits from %d accounts...", NUM_ACCOUNTS);

        for (uint32 i = 0; i < NUM_ACCOUNTS; i++) {
            // Derive the private key for account #i
string memory basePath = "m/44'/60'/0'/0/";
uint256 accountPrivateKey = vm.deriveKey(mnemonic, basePath, i);
            address accountAddress = vm.addr(accountPrivateKey);
            
            // Fund the derived account with a little more than it needs to send
           vm.deal(accountAddress, DEPOSIT_AMOUNT + 1 ether);

            // Switch broadcast to the new account's key
            vm.startBroadcast(accountPrivateKey);

            // Send 50 ETH to the PacketChain contract
            (bool success, ) = address(packetchain).call{value: DEPOSIT_AMOUNT}("");
            require(success, "ETH deposit failed");
            
            console.log("-> Account #%d (%s) deposited %d ETH", i, accountAddress, DEPOSIT_AMOUNT / 1 ether);

            vm.stopBroadcast();
        }
    }
}

