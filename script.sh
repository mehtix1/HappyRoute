#!/bin/bash
# Full setup: ns-3.38 + Foundry + Forge script + ns3 simulation
# Author: Rezo Ghafouri
# Date: 2025-09-23

set -e  # Exit on error

### Step 1: Download ns-3.38
echo "[*] Downloading ns-3.38..."
wget https://www.nsnam.org/releases/ns-allinone-3.38.tar.bz2 -O ns-allinone-3.38.tar.bz2

### Step 2: Extract ns-3.38
echo "[*] Extracting ns-3.38..."
tar -xjf ns-allinone-3.38.tar.bz2

### Step 3: Go into scratch directory
cd ns-allinone-3.38/ns-3.38/scratch/

### Step 4: Create smart folder
echo "[*] Creating scratch/smart..."
mkdir -p smart

### Step 5: Copy files from smart_contract → scratch/smart
echo "[*] Copying smart_contract files..."
cp -r ../../../../smart_contract/* smart/

### Step 6: Install Foundry 1.1.0
echo "[*] Installing Foundry 1.1.0..."
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc || true
source ~/.zshrc || true

### Step 7: Run foundryup inside scratch/smart
cd smart
echo "[*] Running foundryup (v1.1.0) inside scratch/smart..."
foundryup -v 1.1.0

### Step 8: Run forge script
echo "[*] Running forge script..."
forge script script/Counter.s.sol:DeploySimpleStorage \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast \
  --via-ir \
  --optimize \
  --rpc-url http://127.0.0.1:8545

### Step 9: Copy OLSR and AODV modified models into ns-3
cd ../../  # now in ns-3.38 root
echo "[*] Copying custom OLSR model files..."
cp -r ../../olsr/* src/olsr/model/

echo "[*] Copying custom AODV model files..."
cp -r ../../aodv/* src/aodv/model/

### Step 10: Copy vanet_routing_compare.cc into scratch
echo "[*] Copying vanet_routing_compare.cc into scratch..."
cp ../../vanet_routing_compare.cc scratch/

### Step 11: Configure ns-3 with Python bindings
echo "[*] Configuring ns-3..."
./ns3 configure --enable-python-bindings

### Step 12: Build ns-3
echo "[*] Building ns-3..."
./ns3 build

### Step 13: Run VANET simulation
echo "[*] Running VANET scenario..."
NS_LOG="OlsrRoutingProtocol=warn" ./ns3 run "scratch/vanet-routing-compare --scenario=2 --pcap=true --protocol=1" -vvvvv

echo "[✓] All tasks completed successfully!"
