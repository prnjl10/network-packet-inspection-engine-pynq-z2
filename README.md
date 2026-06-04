<div align="center">
  
# Line-Rate Network Packet Inspection Engine on PYNQ-Z2
**A Phased Hardware-Software Co-Design Approach for Deep Packet Inspection (DPI)**

[![Platform](https://img.shields.io/badge/Platform-PYNQ--Z2-orange.svg)]()
[![Vivado](https://img.shields.io/badge/Vivado-2020.2+-blue.svg)]()
[![Language](https://img.shields.io/badge/Language-SystemVerilog%20%7C%20Python-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

</div>

---

## 📖 Abstract
Software-based network packet inspection (e.g., iptables, Snort) is fundamentally bounded by host CPU throughput, kernel-to-userspace copy overhead, and cache behavior. This project presents the design, implementation, and verification of an FPGA-based network packet inspection engine on the Xilinx PYNQ-Z2 development platform that performs deep header inspection at the **AXI-Stream line rate of 1 Gbps**. 

The system is decomposed as a three-stage register-transfer-level (RTL) pipeline communicating with the ARM Cortex-A9 processing system over standard AXI-Stream and AXI-Lite interfaces, exposed to user code through the open-source PYNQ Python framework.

## 🏗️ System Architecture
The architecture is organized as a clean two-domain hardware-software co-design:

### 1. Programmable Logic (PL) Pipeline
The hardware pipeline operates at a 125 MHz clock with a 64-bit data path, yielding a peak internal throughput of 1 Gbps. It consists of three custom RTL modules:
* **Header Parser (`header_parser.sv`):** Accepts AXI-Stream beats, identifies Ethernet, IPv4, and TCP/UDP fields, and emits a structured metadata record.
* **Rule Checker (`rule_checker.sv`):** Consumes metadata and executes parallel comparisons against a software-programmable rule table (5-tuple rules) alongside hard-coded anomaly detectors.
* **Event Packer (`event_packer.sv`):** Maintains protocol-level counters and buffers flagged events into a 256-entry event FIFO accessible via AXI-Lite.

### 2. Processing System (PS) Stack
The PS runs the PYNQ 3.0 Linux distribution. A custom Python overlay class wraps the AXI-Lite register interface to manage the rule table and drain the event FIFO. A live-capture loop based on `scapy` processes frames and visually represents total packet counts, drops, and anomalies via a Jupyter dashboard.

## 📂 Repository Structure

```text
├── docs/                      # Technical documentation and block diagrams
├── hardware/
│   ├── sim/                   # Waveform configurations and Vivado simulation scripts
│   ├── src/                   # Core SystemVerilog RTL modules
│   └── vivado/                # Tcl scripts for block design and bitstream generation
├── software/
│   ├── notebooks/             # Jupyter dashboards for real-time visualization
│   └── overlay/               # Custom Python driver classes, .bit, and .hwh files
└── verification/
    ├── pcap_corpus/           # PCAP files for testbench stimulus
    └── tb/                    # Directed SystemVerilog testbenches
EOF
