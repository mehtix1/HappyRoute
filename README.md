
## Overview  
**HappyRoute** is a system for vehicular ad hoc networks (**VANETs**) which uses blockchain-based incentives to encourage cooperative routing. The idea is to integrate routing protocols (e.g. AODV, OLSR, SMART) with a token-based reward mechanism so that nodes are motivated to honestly forward packets, thereby improving performance and trust in the network.

This repository holds simulation scripts, routing protocol implementations, and incentive integration logic.

---

## Features  
- Integration of classical VANET routing protocols (AODV, OLSR, SMART)  
- Incentive mechanism using blockchain / tokens to reward forwarding  
- Comparative simulation framework to measure performance under incentive vs no incentive  
- Mobility trace / scenario scripts for testing different traffic conditions  
## Prerequisites  

Before building and running HappyRoute, install the following system packages:  

```bash
sudo apt update
sudo apt install -y \
    g++ python3 cmake ninja-build git \
    gir1.2-goocanvas-2.0 python3-gi python3-gi-cairo python3-pygraphviz \
    gir1.2-gtk-3.0 ipython3 tcpdump wireshark \
    sqlite3 libsqlite3-dev \
    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools \
    openmpi-bin openmpi-common openmpi-doc libopenmpi-dev \
    doxygen graphviz imagemagick python3-sphinx dia imagemagick \
    texlive dvipng latexmk texlive-extra-utils texlive-latex-extra texlive-font-utils \
    libeigen3-dev gsl-bin libgsl-dev libgslcblas0 \
    libxml2 libxml2-dev libgtk-3-dev \
    lxc-utils lxc-templates vtun uml-utilities ebtables bridge-utils \
    libboost-all-dev

## Running  

After installing the prerequisites and cloning the repository, you can start the simulation by running:  

```bash
sudo ./script.sh

