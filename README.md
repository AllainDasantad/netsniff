# Netsnif — Network Analyzer

<p align="center">
  A desktop network traffic analyzer built with React, TypeScript, Rust, and Tauri.
</p>

<p align="center">
  <strong>Capture. Inspect. Analyze. Understand.</strong>
</p>

---

## Overview

**Netsnif** is a desktop network analyzer designed to help users monitor and understand network traffic in real time.

It captures network packets from a selected network interface and provides a graphical interface for inspecting packet information, analyzing IP addresses, examining TCP and UDP traffic, and exploring network conversations.

The project is also a practical learning tool for understanding computer networking, packet analysis, and network security.

## Features

- **Dashboard** — Overview of captured network traffic and recent packets.
- **Live Capture** — Capture network packets from a selected interface.
- **Packet Explorer** — Inspect packet details, raw Ethernet frame data, and payload bytes.
- **IP Analysis** — Examine source and destination IP addresses.
- **TCP/UDP Analysis** — Analyze TCP and UDP traffic, ports, and protocol distribution.
- **TCP Streams** — Group packets into bidirectional TCP conversations.
- **Traffic Statistics** — View network traffic statistics and visualizations.

## Technology Stack

| Technology | Purpose |
|---|---|
| React 19 | User interface |
| TypeScript | Type-safe frontend development |
| Vite | Frontend development and build tooling |
| Tauri 2 | Desktop application framework |
| Rust | Backend packet capture and parsing |
| `pcap` | Network packet capture |
| `etherparse` | Ethernet, IP, TCP, and UDP packet parsing |

## Installation

### Requirements

- Linux (developed and tested on Arch-based Linux)
- Node.js and npm
- Rust and Cargo
- Tauri 2 system dependencies
- A network interface
- Appropriate permissions for packet capture

### 1. Clone the repository

```bash
git clone https://github.com/AllainDasantad/netsniff.git
cd netsniff
```

### 2. Install frontend dependencies

```bash
npm install
```

### 3. Run the application

Start the desktop application in development mode:

```bash
npm run tauri dev
```

Vite and Tauri will build and launch the application.

### 4. Build the application

To build the frontend:

```bash
npm run build
```

To build the desktop application:

```bash
npm run tauri build
```

Refer to the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for platform-specific dependencies.

## How to Use Netsnif

### 1. Select a network interface

Open Netsnif and select an available network interface from the sidebar.

Examples of Linux network interfaces:

| Interface | Description |
|---|---|
| `wlan0` | Wireless network interface |
| `eth0` | Ethernet interface |
| `lo` | Loopback interface |

Interface names vary depending on your operating system and hardware.

### 2. Start a capture

Click the **Start Capture** button to begin monitoring traffic.

Netsnif will capture packets from the selected interface and display them in the application.

### 3. Explore captured packets

Open **Packet Explorer** to inspect captured traffic.

You can examine information such as:

- Timestamp
- Source and destination addresses
- Protocol
- Source and destination ports
- Packet size
- Raw packet bytes
- Payload bytes

### 4. Analyze network traffic

Use the analysis pages to understand different aspects of your captured traffic:

- **IP Analysis:** Examine communication between IP addresses.
- **TCP/UDP Analysis:** Compare transport protocols and inspect port usage.
- **TCP Streams:** Explore packets belonging to TCP conversations.
- **Traffic Statistics:** Review traffic distribution and packet statistics.

### 5. Stop the capture

Click **Stop Capture** when you have finished monitoring.

The application stops collecting new packets.

## Networking Fundamentals

Understanding these concepts will help you use Netsnif effectively.

### What is a network packet?

A network packet is a formatted unit of data transmitted across a network.

A packet generally contains control information in headers and may contain application data.

When you visit a website, send a message, or download a file, your device exchanges network traffic with other devices.

### MAC Address

A **Media Access Control (MAC) address** identifies a network interface at the data-link layer.

Example:

```text
00:1A:2B:3C:4D:5E
```

MAC addresses are commonly used for communication within a local network.

### IP Address

An **Internet Protocol (IP) address** identifies a network interface for communication across IP networks.

Examples:

```text
IPv4: 192.168.1.10
IPv6: 2001:db8::1
```

IP addresses help devices and routers identify where packets should be delivered.

### TCP — Transmission Control Protocol

TCP is a connection-oriented transport protocol.

It provides reliable, ordered delivery of a byte stream using mechanisms such as acknowledgments, sequence numbers, and retransmissions.

Common examples of TCP usage include:

- HTTPS
- SSH
- Email
- File transfers

TCP commonly uses a three-way handshake to establish a connection:

```text
Client                  Server
  |                        |
  |-------- SYN ---------->|
  |<----- SYN-ACK ---------|
  |-------- ACK ---------->|
  |                        |
  |    Connection Ready    |
```

### UDP — User Datagram Protocol

UDP is a connectionless transport protocol.

It has less built-in communication overhead than TCP, but it does not guarantee delivery, ordering, or duplicate protection.

Common examples include:

- DNS queries
- Voice and video applications
- Online gaming
- Real-time communication

### TCP vs UDP

| Feature | TCP | UDP |
|---|---|---|
| Connection | Connection-oriented | Connectionless |
| Delivery guarantee | Reliable delivery | No delivery guarantee |
| Ordering | Ordered byte stream | No ordering guarantee |
| Overhead | Generally higher | Generally lower |
| Common uses | HTTPS, SSH | DNS, real-time traffic |

### Port Numbers

Port numbers help identify application services on a device.

Examples:

| Port | Common Service |
|---|---|
| 22 | SSH |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 5353 | mDNS |

A port number alone does not prove which application generated a packet, but it can provide useful context.

## Understanding a Packet

A simplified packet structure looks like this:

```text
+-----------------------------+
|       Ethernet Header       |
+-----------------------------+
|          IP Header          |
+-----------------------------+
|     TCP or UDP Header       |
+-----------------------------+
|        Payload Data         |
+-----------------------------+
```

Each layer provides information needed to deliver and process network traffic.

The exact structure depends on the protocols used. For example, IPv4 and IPv6 have different IP header formats.

## Current Limitations

Netsnif is an educational project and is still under development.

Current limitations include:

- TCP stream grouping does not yet reconstruct the complete application byte stream.
- TCP sequence-number reassembly is not implemented.
- Fragment reassembly is not implemented.
- Encrypted TLS application data cannot be interpreted as plaintext by simply inspecting captured payload bytes.
- Packet capture depends on operating-system permissions and supported interfaces.
- Packet storage is currently limited to the latest 1,000 captured packets.

## Security and Responsible Use

Netsnif is intended for educational purposes, network troubleshooting, and authorized network monitoring.

**Only capture traffic on networks and devices you own or have explicit permission to monitor.**

Captured packets may contain sensitive information, including IP addresses, device identifiers, and application metadata.

Always handle captured network data responsibly.

## Learning Resources

- [RFC 9293 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 768 — User Datagram Protocol](https://www.rfc-editor.org/rfc/rfc768)
- [Cloudflare Learning Center — Networking](https://www.cloudflare.com/learning/network-layer/what-is-a-computer-network/)
- [Tauri Documentation](https://v2.tauri.app/)
- [Rust Documentation](https://doc.rust-lang.org/book/)

## Future Improvements

Potential future development:

- Advanced packet filtering
- TCP stream reassembly
- Packet export to PCAP format
- DNS analysis
- Improved IPv6 parsing
- Capture session management
- More detailed protocol statistics

## Author

**AllainDasantad**

GitHub: https://github.com/AllainDasantad

## License

Add your chosen open-source license here. If you intend to publish this project for public use, consider adding an MIT License file.
