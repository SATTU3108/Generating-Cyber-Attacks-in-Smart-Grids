# Smart Grid Cyber-Physical Testbed for Cybersecurity Analysis

This repository contains the implementation and documentation of a **Cyber-Physical Testbed for Smart Grids** that integrates the **Real-Time Digital Simulator (RTDS)**, **RSCAD**, and the **ns-3 network simulator**.  
The testbed is designed to simulate realistic cyberattacks (MITM, ARP spoofing, DNP3 data modification, etc.) on power system communication protocols like **DNP3** and **IEEE C37.118 (PMU streams)**, enabling the study of their impact on grid operation, control, and resilience.

---

## 🧠 Project Overview

With the increasing digitization of the power grid, Supervisory Control and Data Acquisition (SCADA) and synchrophasor systems have become vulnerable to cyberattacks.  
This project aims to **simulate, intercept, and analyze** communication between the **RTDS GTNET card** and control center applications such as **OpenHistorian** or **RSCAD P&A Suite** through a programmable **ns-3 layer** acting as a cyberattack emulator.

The testbed enables controlled execution of attacks to observe both **physical effects (breaker status, power flow)** and **cyber traces (packet manipulation, spoofing, delays)**.

---

## ⚙️ System Architecture

The overall setup involves three major layers:

1. **Power System Simulation (RSCAD / RTDS)**
   - IEEE 14-bus power network modeled in RSCAD Draft.
   - Real-time execution on RTDS generating PMU or DNP3 data.
   - Communication via GTNET card.

2. **Cyber Layer (ns-3)**
   - Acts as a programmable intermediary between GTNET and Control Center.
   - Tap-based bridging (`tap00`, `tap01`) connected via Linux bridges (`br0`, `br1`).
   - Capable of intercepting and modifying live packets using `attack-app` and `ns3.conf`.

3. **Control and Monitoring Layer**
   - Consists of OpenHistorian or RSCAD P&A Suite.
   - Receives the modified (or spoofed) PMU/DNP3 data.
   - Used to visualize and verify the effect of attacks.

---

## 🔍 Features

- Real-time packet interception between RTDS and historian/control center.
- Protocol-level modification (DNP3, PMU/IEEE C37.118).
- Man-in-the-Middle and ARP spoofing emulation.
- Offline packet analysis with **Wireshark** and **tcpdump**.
- Attack configuration via `ns3.conf` file (function codes, DNP3 groups, variations).
- Seamless integration with RTDS hardware interfaces and virtual TAP bridges.

---

## 🧩 Repository Structure
