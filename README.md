# Network Packet Inspection Engine on PYNQ-Z2
A hardware-accelerated deep network packet inspection reference design on the Xilinx Zynq-7020 (PYNQ-Z2), implementing a 1 Gbps AXI-Stream RTL pipeline with a PYNQ Python hardware-software co-design.
## Project Phases
- **Phase 1 (Complete):** Pipelined RTL deep header inspection for Ethernet, IPv4, TCP, and UDP, packaged as a reusable AXI-Stream IP with hardware anomaly detection. Validated on PYNQ-Z2 hardware via a Python overlay driver and live traffic dashboard.
- **Phase 2 (Planned):** Hardware streaming bytestring payload matcher integrated with the parser for single-pattern Deep Packet Inspection (DPI).
## Repository Structure
| Folder | Contents |
|---|---|
| `docs/` | Project documentation and architecture/diagram images |
| `hardware/` | SystemVerilog RTL source (pipeline modules and shared package) |
| `software/` | Python PYNQ overlay class and Jupyter live-demonstration notebook |
| `verification/` | Self-checking SystemVerilog testbenches |
## Hardware / Tools
- Board: PYNQ-Z2 (Xilinx Zynq-7020)
- Toolchain: Vivado 2022.2, PYNQ 3.0
- Languages: SystemVerilog, Python 3
## Status
Phase 1: Complete — validated on PYNQ-Z2 hardware.
Phase 2: In progress!
## Live Demo
The notebook in `software/` streams synthetic mixed traffic through the engine on the board and reads the inspector's counters back over AXI-Lite in real time.

<img width="493" height="164" alt="image" src="https://github.com/user-attachments/assets/e9dcacaf-2a85-4824-87fd-da499ae96224" />


- **Left — cumulative classification:** total packets inspected versus how many were dropped, passed, and flagged as anomalies, accumulating as traffic is injected.
- **Right — per-rule and per-anomaly hits:** which detector is firing. Rule 0 ("drop all TCP") catches every TCP packet, and anomaly detector 1 (illegal TCP SYN+FIN) catches the malformed frames.

Final run: **703 packets** inspected, **492 dropped** by rule 0, and **158 SYN+FIN anomalies** flagged, all read from the hardware counters, not simulated.
