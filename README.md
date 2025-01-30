from pathlib import Path

# Creating the README.md content
readme_content = """# Packet Generator (Enterprise)

This repository contains an enterprise-level Packet Generator application designed with Python's Tkinter GUI framework. The program is a comprehensive packet generation and testing tool with features like persistent settings, lost-packet tracking, and network link monitoring.

## Features
- **Persistent Settings:** Saves and loads configurations using a JSON file.
- **Advanced Packet Options:** Toggle between adding timestamps, random bytes, client IDs, and GPS coordinates to packets.
- **Lost Packet Tracking:** Sequence number verification to track any lost packets during transmission.
- **Link Monitoring:** Network link LEDs provide real-time interface status.
- **Customizable:** Configure packet size, transmission rate, and maximum packet count.
- **GUI Locking:** The GUI window is locked for stability during operations.

## Requirements
- Python 3.x
- `tkinter` for GUI components
- `psutil` for network interface monitoring

## Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_folder>
