# Packet Generator (Enterprise)

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
   ```

2. Install necessary dependencies:
   ```bash
   pip install psutil
   ```

3. Run the application:
   ```bash
   python PacGen11.py
   ```

## Configuration
Settings are saved in a file called `packet_gen_config.json`. Upon startup, the application will automatically load any previously saved configurations or use default settings.

## Usage
1. **Select Ports:** Choose sender and receiver ports using the dropdown menus.
2. **Set Target:** Enter the target IP and port for packet transmission.
3. **Configure Packet Details:** Customize packet size, transmission rate, and other options using the GUI.
4. **Start Transmission:** Click the "Start" button to begin sending packets.
5. **Monitor Progress:** The status bar and counters will provide real-time feedback on the transmission process.

## Contributing
Feel free to contribute to this project by forking the repository and submitting pull requests. Ensure your changes are well-documented.

## License
This project is licensed under the MIT License.

## Acknowledgments
Special thanks to the open-source community for providing valuable libraries and inspiration for this project.
