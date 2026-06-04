# Line-Rate Network Packet Inspection Engine on PYNQ-Z2

An open-source, hardware-accelerated Network Packet Inspection (NPI) Engine implemented on the Xilinx PYNQ-Z2 development board. The system utilizes a three-stage SystemVerilog pipeline to perform deep header inspection at a 1 Gbps AXI-Stream line rate (125 MHz clock @ 64-bit data path), backed by a Python-based Jupyter user-space dashboard.

## 📂 Repository Structure
* **docs/** - System block diagrams and technical specifications
* **hardware/** - SystemVerilog RTL modules, XSIM configs, and Vivado Tcl scripts
* **software/** - Custom PYNQ Python drivers, bitstreams, and Jupyter notebooks
* **verification/** - Module-level/top-level testbenches and PCAP test vectors
