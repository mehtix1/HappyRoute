// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PacketChain {
    struct Packet {
        address proposer;
        address current;
        address last;
        uint256 id;
        bytes32 secret;
        uint256 hops;
        bool claimed;
    }
    uint256[] private freeIds;
    mapping(uint256 => Packet) public packets;
    mapping(address => uint256) public balances; // ledger-style balances
    uint256 private nextId = 1;

    event PacketCreated(uint256  indexed id, address indexed from, address indexed to, uint256 hops, bytes32 secret);
    event PacketForwarded(uint256 indexed id, address from, address to, uint256 hopsLeft);
    event PacketDelivered(uint256 indexed id, address finalReceiver);
    event PacketClaimed(uint256 indexed id, address indexed receiver, uint256 amount);
    event BalanceChanged(address indexed user, int256 amount, uint256 newBalance);


    /// @notice Deposit ETH into your internal balance
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw ETH from your internal balance
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Withdraw failed");
        //emit BalanceChanged(msg.sender, -int256(amount), balances[msg.sender]);
    }

    /// @notice Create or forward a packet
    function makeChain(
        uint256 hops,
        bytes32 secret,
        address nextHop,
        uint256 id
    ) external {
        require(hops > 0, "Hops must be greater than 0");
        require(nextHop != address(0), "NextHop cannot be zero");
        uint256 cost = hops * 1 ether;
        require(balances[msg.sender] >= cost, "Insufficient balance");
        balances[msg.sender] -= cost;
        //emit BalanceChanged(msg.sender, -int256(cost), balances[msg.sender]);
        if (id == 0) {
            // New packet: charge sender upfront


            // Create new packet
            if (freeIds.length > 0) {
           // If there's a free ID, take the last one from the list
           id = freeIds[freeIds.length - 1];
           freeIds.pop();
           } else {
               // Otherwise, create a new one
               id = nextId++;
           }
            packets[id] = Packet({
                proposer: msg.sender,
                current: msg.sender,
                last: address(0),
                id: id,
                secret: secret,
                hops: hops,
                claimed: false
            });

            emit PacketCreated(id, msg.sender, nextHop, hops, secret);
        } 
            // Forward existing packet
            Packet storage packet = packets[id];
            require(packet.id != 0, "Packet does not exist");
            require(!packet.claimed, "Packet already claimed");
            
            // Secret check
        if (packet.secret != bytes32(0)) { // A more efficient check for an empty secret
            require(packet.secret == secret, "Invalid secret"); // <-- CHANGED to a simple ==
        }

            require(packet.hops > 0, "No hops left");
            if (packet.last != address(0) && packet.last !=packet.proposer ) {
                uint256 reward = packet.hops + 2; // in ether units
                balances[packet.last ] += reward * 1 ether;
                //emit BalanceChanged(packet.last , int256(reward * 1 ether), balances[packet.last ]);
            }
            // Update
            packet.hops -= 1;
            address prev = packet.current;
            packet.last = prev;
            packet.current = nextHop;

            emit PacketForwarded(id, prev, nextHop, packet.hops);




    }

    /// @notice Claim final payment as the current hop
    function receivePacket(uint256 id, bytes32 secret) external {
        Packet storage packet = packets[id];
        require(packet.id != 0, "Invalid packet id");
        require(!packet.claimed, "Already claimed");
        require(packet.current == msg.sender, "Not current hop");

        // Secret check
        if (packet.secret != bytes32(0)) {
            require(packet.secret == secret, "Invalid secret"); // <-- CHANGED to a simple ==
        }
        packet.claimed = true;

        // Credit 1 ether to the current hop
        balances[packet.current] += 1 ether;
        balances[packet.last] += 2 ether;
        //emit BalanceChanged(packet.current, int256(1 ether), balances[packet.current]);
       //emit BalanceChanged(packet.last, int256(1 ether), balances[packet.last]);
        emit PacketClaimed(id, packet.current, 1 ether);

        // Cleanup

        freeIds.push(id); // Add the ID to the list of free IDs
        delete packets[id];
    }

    /// @notice Allow contract to receive ETH
    receive() external payable {}
}

