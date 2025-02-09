
# Enterprise Packet Generator (Enterprise Professional Edition)

![Enterprise Packet Generator](https://via.placeholder.com/600x200?text=Enterprise+Packet+Generator+Logo)

## Overview

The **Enterprise Packet Generator (Enterprise Professional Edition)** is a work-in-progress Python application designed to generate high-performance network traffic over **UDP** or **TCP**. This application provides features such as sequence tracking, HMAC-based payload authentication, CRC validation, and complete customization of packet headers and payloads. It is intended for testing network infrastructure under controlled, reproducible traffic conditions.

With support for multiple TX/RX ports, detailed performance monitoring, and configurable features, the tool is ideal for benchmarking, reliability testing, and identifying potential bottlenecks in network environments.

---

## Features

- **Protocols:** Choose between UDP or TCP for packet transmission.
- **Sequence Tracking:** Packets include 4-byte sequence headers for proper ordering.
- **HMAC and CRC:** Optionally add HMAC signatures for payload authentication and CRC32 checksum verification.
- **Multiple Ports:** Supports 4 configurable network ports for TX/RX.
- **Physical Interface Binding:** Binds to physical interfaces using `SO_BINDTODEVICE` (Linux) or `SO_DONTROUTE` (Windows).
- **Customizable Packet Structure:** Include protocol version, source MAC address, UUID, and more in packet headers.
- **GUI Interface:** Easy-to-use graphical user interface built with **Tkinter**.
- **Live Performance Monitoring:** Instantaneous and average speed metrics displayed in real time.
- **Configurable:** Save and load configuration settings using JSON.

---

## Screenshot

![GUI Screenshot](https://via.placeholder.com/800x450?text=GUI+Screenshot)

---

## Installation

### Prerequisites
- **Python 3.7+**
- **psutil**
  
  Install using:
  ```bash
  pip install psutil
  ```

### Clone the Repository
```bash
git clone https://github.com/your-username/enterprise-packet-generator.git
cd enterprise-packet-generator
```

### Run the Application
```bash
python3 packet_generator.py
```

---

## Configuration

Settings are saved in `packet_gen_config.json`. The GUI allows on-the-fly modifications to:
- Target port
- Packet size
- Packets per second
- Maximum packets to send
- Protocol selection (UDP/TCP)
- Advanced options such as HMAC, CRC, MAC address inclusion, and more.

---

## Usage

1. **Start the Application:** Launch using the command mentioned in the installation section.
2. **Configure Ports:** Select TX/RX interfaces for UDP/TCP communication.
3. **Set Parameters:** Adjust packet size, speed, and header options.
4. **Monitor:** Track live performance metrics including packet loss, errors, and speed.
5. **Stop/Reset:** Stop the current session and reset counters for a new test.

---

## Important Notes

- This tool is intended for advanced users and professionals conducting network tests.
- Ensure the correct physical network interfaces are selected to observe packet behavior accurately.

---

## Authors and Acknowledgments

This project is a work in progress developed with contributions from **Adam Figueroa** and guidance from **Chat-GPT**.

We are actively working on expanding the tool's capabilities and addressing any issues reported by users. If you encounter problems or have suggestions, feel free to open an issue on GitHub.

---

## Roadmap

Planned features include:
- Expanded protocol support (e.g., ICMP, custom protocols)
- Enhanced latency measurement and reporting
- Automated stress testing scripts
- Support for distributed deployments

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

---

## Disclaimer

This tool is for testing purposes only. Improper use may cause network congestion or other issues. Please use responsibly.

---

## Download

You can download this README file directly: [README.md](./README.md)
