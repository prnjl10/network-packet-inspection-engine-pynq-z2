# Network Packet Inspection Engine on PYNQ-Z2

A hardware-accelerated deep network packet inspection reference design on the Xilinx Zynq-7020 (PYNQ-Z2), implementing a 1 Gbps AXI-Stream RTL pipeline with a PYNQ Python hardware-software co-design.

## Project Phases

- **Phase 1 (In progress):** Pipelined RTL deep header inspection for Ethernet, IPv4, TCP, and UDP, packaged as a reusable AXI-Stream IP with hardware anomaly detection.
- **Phase 2 (Planned):** Hardware streaming bytestring payload matcher integrated with the parser for single-pattern Deep Packet Inspection (DPI).

## Repository Structure

| Folder | Contents |
|---|---|
| `docs/` | Project documentation, architecture diagrams, specifications |
| `hardware/` | SystemVerilog RTL source, testbenches, and Vivado project scripts |
| `software/` | Python PYNQ overlay classes and Jupyter live-demonstration notebooks |
| `verification/` | Top-level testbenches and PCAP-replay sample data |

## Hardware / Tools

- Board: PYNQ-Z2 (Xilinx Zynq-7020)
- Toolchain: Vivado 2020.2+, PYNQ 3.0
- Languages: SystemVerilog, Python 3

## Status

Phase 1: In progress!

