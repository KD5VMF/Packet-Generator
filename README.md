# Packet Generator (Enterprise Edition)

Use PacGen35.py or The PacGen32 ZIP file for an easy run, but older version. (01/31/2025)

Rev update: PacGen38.py Has many updates including a live Graph!

## Overview
The **Packet Generator (Enterprise Edition)** is a highly configurable, robust network packet generation tool with a feature-rich GUI built using **Tkinter**. Designed to meet enterprise-level demands, it supports persistent configurations, real-time speed monitoring, enhanced packet options, and an autotuning mechanism for dynamic performance adjustment.

---

## Key Features

- **Graphical User Interface (GUI):** Built using Tkinter with resizable, interactive widgets.
- **Real-time speed monitoring:** Displays network speed in KB/s, MB/s, and Mbps.
- **Persistent Configuration:** Automatically saves and loads settings using a JSON configuration file.
- **Enhanced Packet Customization:** Optional protocol versioning, source MAC address, unique packet IDs, and payload signatures.
- **Autotune Feature:** Automatically adjusts packet size and packets per second (PPS) to maintain optimal performance.
- **Lost Packet Detection:** Tracks lost packets using sequence numbers.
- **Handshake Support:** Optional initial handshake to ensure reliable communication.
- **Link LED Indicators:** Monitors source and destination link status with real-time updates.
- **Multi-threaded Design:** Background threads for packet sending, receiving, and autotuning.

---

## Requirements

- **Python 3.8+**
- **Tkinter** (included with most Python installations)
- **Psutil** library for network interface detection

You can install `psutil` using:

```bash
pip install psutil
```

---

## Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/packet-generator-enterprise.git
   cd packet-generator-enterprise
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt  # Include psutil as a dependency
   ```

3. Run the application:
   ```bash
   python packet_generator.py
   ```

---

## Application Layout

- **Network Configuration:** Select source and destination network interfaces.
- **Target Configuration:** Specify the target IP address and port.
- **Packet Settings:** Configure packet size, packets per second, and maximum packets.
- **Enhanced Features:** Enable/disable optional protocol enhancements.
- **Autotune:** Enable dynamic performance tuning.
- **Link Status LEDs:** Monitor real-time link status.
- **Debug Log:** View system events, logs, and errors.

---

## Usage Instructions

1. Launch the application using the command:
   ```bash
   python packet_generator.py
   ```

2. Configure the **Network Settings**:
   - Select source and destination network interfaces from the dropdown.
   - Set the target IP and port.

3. Adjust **Packet Settings**:
   - Define the packet size and packets per second.
   - Optionally, set a maximum packet limit (0 for unlimited).

4. Customize the **Enhanced Features**:
   - Enable options like protocol versioning, source MAC, and unique packet IDs.

5. Enable or disable **Autotune**:
   - If enabled, the tool dynamically adjusts packet size and PPS based on performance.

6. Click **Start** to begin sending packets and **Stop** to end the process.

---

## Autotune Mechanism

The autotune feature dynamically adjusts packet size and packets per second (PPS) based on network conditions:

- **Increase PPS/Size:** When no packet loss is detected for a set threshold.
- **Decrease PPS/Size:** When packet loss or network errors are detected.

---

## Configuration File

The application saves settings in a JSON configuration file named `packet_gen_config.json` located in the project directory. Upon startup, it loads these settings automatically.

**Sample Configuration:**
```json
{
  "source_port": "",
  "destination_port": "",
  "target_ip": "",
  "target_port": 12345,
  "packet_size": 32768,
  "packets_per_second": 1000,
  "max_packets": 0,
  "use_handshake": false,
  "use_start_delay": false,
  "use_verbose": false,
  "add_protocol_version": false,
  "add_source_mac": false,
  "add_unique_id": false,
  "add_payload_signature": false,
  "autotune_enabled": true,
  "autotune_interval": 5,
  "autotune_packs_increment": 50,
  "autotune_packs_decrement": 50,
  "autotune_size_increment": 500,
  "autotune_size_decrement": 500,
  "max_packet_size": 32768,
  "max_packs_per_sec": 5000,
  "min_packs_per_sec": 50,
  "min_packet_size": 5000
}
```

---

## Development and Contribution

We welcome contributions to enhance the Packet Generator further! To contribute:

1. Fork the repository.
2. Create a new branch.
3. Commit your changes.
4. Submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Troubleshooting

- **Error: The 'psutil' library is required but not installed:**
  - Install it using `pip install psutil`.
- **Link LED not updating:**
  - Ensure the selected network interfaces are active and properly configured.
- **Packet loss detected:**
  - Try enabling the autotune feature to dynamically adjust performance.


---

## Acknowledgments

Special thanks to the open-source community for their contributions to networking libraries and frameworks.

---

## Contact

For questions or support, please contact:

- **Author:** ChatGPT 4 & KD5VMF 
