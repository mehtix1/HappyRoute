// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/SimpleChannelManager.sol";

contract PacketChainTest is Test {
    PacketChain packetChain;

    address A = address(0xA);
    address B = address(0xB);
    address C = address(0xC);
    address D = address(0xD);
    address E = address(0xE);

    function setUp() public {
        packetChain = new PacketChain();

        // fund A with 10 ether
        vm.deal(A, 10 ether);
        vm.deal(B, 10 ether);
        vm.deal(C, 10 ether);
        vm.deal(D, 10 ether);

        // A deposits 3 ether into contract
        vm.startPrank(A);
        packetChain.deposit{value: 4 ether}();
        vm.stopPrank();
        vm.startPrank(B);
        packetChain.deposit{value: 3 ether}();
        vm.stopPrank();
        vm.startPrank(C);
        packetChain.deposit{value: 2 ether}();
        vm.stopPrank();
        vm.startPrank(D);
        packetChain.deposit{value: 1 ether}();
        vm.stopPrank();
    }




    /// @notice Tests that the PacketCreated event is emitted with the correct arguments.
    function test_makeChain_emits_PacketCreated() public {

        // --- Setup ---
        uint256 hops = 5;
        string memory secret = "my-secret-password";
        uint256 id = 0; // Signifies a new packet

        // The proposer needs to deposit funds first to cover the cost.
        uint256 cost = hops * 1 ether;
        vm.prank(A); // Set the next transaction's msg.sender
        packetChain.deposit{value: cost}();

        // --- Action & Assertion ---

        // 1. Tell Foundry to expect an event.
        // We check all 3 indexed topics (id, from, to) and the data (hops, secret).
        vm.expectEmit(true, true, true, true);

        // 2. Specify the exact event signature and data you expect.
        emit PacketChain.PacketCreated(1, A, B, hops, secret);

        // 3. Call the function that should emit the event.
        vm.prank(A);
        packetChain.makeChain(hops, secret, B, id);
    }






    function testPacketChain_AtoE() public {
        string memory secret = "secretX";

        vm.startPrank(A);
        packetChain.makeChain(4, secret, B, 0);
        vm.stopPrank();

        //--------------------------------------//
        assertEq(packetChain.balances(A), 0 ether, "A should net 0");

        // ---- STEP 2: Forward to B ----
        vm.startPrank(B);
        packetChain.makeChain(3, secret, C, 1); // id=1
        vm.stopPrank();
        assertEq(packetChain.balances(B), 0 ether, "B should net 0");

        // ---- STEP 3: Forward to C ----
        vm.startPrank(C);
        packetChain.makeChain(2, secret, D, 1);
        vm.stopPrank();
assertEq(packetChain.balances(C), 0 ether, "C should net 0");
        // ---- STEP 4: Forward to D ----
        vm.startPrank(D);
        packetChain.makeChain(1, secret, E, 1);
        vm.stopPrank();
assertEq(packetChain.balances(D), 0 ether, "D should net 0");
        // ---- STEP 5: D claims ----
        vm.startPrank(E);
        packetChain.receivePacket(1, secret);
        vm.stopPrank();

        // ---- Assertions ----
        assertEq(packetChain.balances(A), 0 ether, "A should net 0");
        assertEq(packetChain.balances(B), 4 ether, "B should have 2 ETH");
        assertEq(packetChain.balances(C), 3 ether, "C should have 1 ETH");
        assertEq(packetChain.balances(D), 2 ether, "D should have 1 ETH");
        assertEq(packetChain.balances(E), 1 ether, "E is never reached");
    }
}

