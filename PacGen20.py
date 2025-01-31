import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import socket
import psutil
import time
import struct
import hashlib
import json
import os
import random
import datetime
import zlib
import traceback
import sys

# Configuration file for persistent settings
CONFIG_FILE = "packet_gen_config.json"

class PacketGeneratorApp:
    """
    A Packet Generator with enterprise-level features:
      - Persistent settings in JSON
      - Fancy checkboxes (handshake, start delay, verbose logging)
      - Additional data toggles (timestamp, random bytes, client ID, GPS)
      - Lost packet tracking via sequence numbers
      - Automatic stop at a max packet count
      - Link LEDs and a locked GUI window
      - Autotune feature to adjust packet size and packets per second based on packet loss
      - Real-time speed display (KB/s, MB/s)
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Packet Generator (Enterprise)")

        # State / Counters
        self.running = False
        self.packet_count = 0
        self.received_packet_count = 0
        self.error_count = 0

        # Lost-packet tracking
        self.lost_packets = 0
        self.last_received_seq = -1

        # Sockets / Threads
        self.sock = None
        self.recv_sock = None
        self.receiver_thread = None
        self.autotune_thread = None
        self.autotune_running = False

        # For "no new packets" warnings
        self.last_received_check_count = 0

        # Bytes sent in the last interval (for speed calculation)
        self.bytes_sent_last_interval = 0

        # Lock for thread-safe operations
        self.lock = threading.Lock()

        # Default config
        self.default_settings = {
            "source_port": "",
            "destination_port": "",
            "target_ip": "",
            "target_port": 12345,
            "packet_size": 512,  # Reduced from 1024 to 512
            "packets_per_second": 100,  # Reduced from 1000 to 100
            "max_packets": 0,  # 0 => infinite
            # Fancy checkboxes
            "use_handshake": False,
            "use_start_delay": False,
            "use_verbose": False,
            # Four new data toggles
            "add_timestamp": False,
            "add_random": False,
            "add_client_id": False,
            "add_gps": False,
            # Autotune settings
            "autotune_enabled": True,
            "autotune_interval": 5,  # seconds
            "autotune_loss_threshold_high": 5,  # percent
            "autotune_loss_threshold_low": 2,   # percent
            "autotune_packs_increment": 10,     # packets per second
            "autotune_packs_decrement": 10,     # packets per second
            "autotune_size_increment": 1024,    # bytes
            "autotune_size_decrement": 1024,    # bytes
            "max_packet_size": 32768,           # Maximum packet size
            "max_packs_per_sec": 300,           # Maximum packets per second
            "min_packs_per_sec": 10,            # Minimum packets per second
            "min_packet_size": 256,             # Minimum packet size
        }

        # Load user settings
        self.user_settings = self.load_config()

        # Initialize status_text before creating widgets
        self.status_text = tk.StringVar(value="Status: Ready")

        # Build GUI
        self.create_widgets()

        # Detect network interfaces
        self.detect_network_ports()

        # Apply loaded settings to the GUI
        self.apply_loaded_settings()

        # Friendly startup message
        self.log("Welcome to Packet Generator (Enterprise)!")
        if os.path.isfile(CONFIG_FILE):
            self.log("Your settings have been loaded from configuration.")
        else:
            self.log("No config found; using defaults.")

        # Monitor link LEDs periodically
        self.monitor_link_status()

        # Check receiving activity periodically
        self.root.after(2000, self.check_receive_activity)

        # Start autotune if enabled
        if self.user_settings.get("autotune_enabled", True):
            self.start_autotune()

        # Start speed update loop
        self.update_speed()

        # Save config on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Maximize the window on startup
        self.maximize_window()

    def maximize_window(self):
        """Maximize the window based on the operating system."""
        if sys.platform.startswith('win'):
            self.root.state('zoomed')
        elif sys.platform.startswith('darwin'):
            self.root.attributes('-zoomed', True)
        else:
            self.root.attributes('-fullscreen', True)

    def load_config(self):
        """Load settings from JSON or return defaults."""
        if os.path.isfile(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                for k, v in self.default_settings.items():
                    data.setdefault(k, v)
                return data
            except Exception as e:
                self.log(f"Error loading config: {e}. Using defaults.")
                return dict(self.default_settings)
        else:
            return dict(self.default_settings)

    def save_config(self):
        """Save current settings to JSON."""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.user_settings, f, indent=2)
            self.log("Configuration saved successfully.")
        except Exception as e:
            self.log(f"Error saving config: {e}")

    def on_close(self):
        """On close: save config, stop activity, destroy root."""
        self.update_user_settings()
        self.save_config()
        self.stop_sending()
        self.stop_receiver()
        self.stop_autotune()
        self.root.destroy()

    def update_user_settings(self):
        """Pull UI fields into self.user_settings dict."""
        self.user_settings["source_port"] = self.source_port.get()
        self.user_settings["destination_port"] = self.destination_port.get()
        self.user_settings["target_ip"] = self.target_ip.get()
        self.user_settings["target_port"] = self.target_port.get()
        self.user_settings["packet_size"] = self.packet_size.get()
        self.user_settings["packets_per_second"] = self.packets_per_second.get()
        self.user_settings["max_packets"] = self.max_packets.get()

        self.user_settings["use_handshake"] = bool(self.var_handshake.get())
        self.user_settings["use_start_delay"] = bool(self.var_start_delay.get())
        self.user_settings["use_verbose"] = bool(self.var_verbose.get())

        self.user_settings["add_timestamp"] = bool(self.var_timestamp.get())
        self.user_settings["add_random"] = bool(self.var_random.get())
        self.user_settings["add_client_id"] = bool(self.var_clientid.get())
        self.user_settings["add_gps"] = bool(self.var_gps.get())

        # Autotune settings
        self.user_settings["autotune_enabled"] = bool(self.var_autotune.get())

    def apply_loaded_settings(self):
        """Set combos, entries, checkboxes from user_settings."""
        source_vals = self.source_port_combo["values"]
        destination_vals = self.destination_port_combo["values"]

        if self.user_settings["source_port"] in source_vals:
            self.source_port.set(self.user_settings["source_port"])
        if self.user_settings["destination_port"] in destination_vals:
            self.destination_port.set(self.user_settings["destination_port"])

        self.target_ip.set(self.user_settings["target_ip"])
        self.target_port.set(self.user_settings["target_port"])
        self.packet_size.set(self.user_settings["packet_size"])
        self.packets_per_second.set(self.user_settings["packets_per_second"])
        self.max_packets.set(self.user_settings["max_packets"])

        self.var_handshake.set(self.user_settings["use_handshake"])
        self.var_start_delay.set(self.user_settings["use_start_delay"])
        self.var_verbose.set(self.user_settings["use_verbose"])

        self.var_timestamp.set(self.user_settings["add_timestamp"])
        self.var_random.set(self.user_settings["add_random"])
        self.var_clientid.set(self.user_settings["add_client_id"])
        self.var_gps.set(self.user_settings["add_gps"])

        self.var_autotune.set(self.user_settings.get("autotune_enabled", True))

    def create_widgets(self):
        """Build all GUI widgets: combos, entries, checkboxes, debug area."""
        # Configure grid layout for root
        self.root.grid_columnconfigure(0, weight=1)
        for col in range(10):
            self.root.grid_columnconfigure(col, weight=1)
        self.root.grid_rowconfigure(9, weight=1)  # Make debug log area expandable

        # Title Frame
        title_frame = ttk.Frame(self.root)
        title_frame.grid(row=0, column=0, columnspan=10, pady=10, sticky="ew")
        title_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(title_frame, text="Packet Generator", font=("Helvetica", 20)).pack(fill='x')

        # Network Configuration Frame
        net_config_frame = ttk.LabelFrame(self.root, text="Network Configuration")
        net_config_frame.grid(row=1, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(8):
            net_config_frame.grid_columnconfigure(col, weight=1)

        # Source Port
        ttk.Label(net_config_frame, text="Select Source Port:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.source_port = tk.StringVar()
        self.source_port_combo = ttk.Combobox(net_config_frame, textvariable=self.source_port,
                                             state="readonly")
        self.source_port_combo.grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        # Destination Port
        ttk.Label(net_config_frame, text="Select Destination Port:").grid(row=0, column=2, sticky="e", padx=5, pady=2)
        self.destination_port = tk.StringVar()
        self.destination_port.trace("w", self.auto_set_target_ip)
        self.destination_port_combo = ttk.Combobox(net_config_frame, textvariable=self.destination_port,
                                                 state="readonly")
        self.destination_port_combo.grid(row=0, column=3, padx=5, pady=2, sticky="ew")

        # Link LEDs
        ttk.Label(net_config_frame, text="Source Link:").grid(row=0, column=4, sticky="e", padx=5, pady=2)
        self.source_link_led = tk.Canvas(net_config_frame, width=20, height=20, bg="gray")
        self.source_link_led.grid(row=0, column=5, padx=5, pady=2)

        ttk.Label(net_config_frame, text="Destination Link:").grid(row=0, column=6, sticky="e", padx=5, pady=2)
        self.destination_link_led = tk.Canvas(net_config_frame, width=20, height=20, bg="gray")
        self.destination_link_led.grid(row=0, column=7, padx=5, pady=2)

        # Target IP and Port Frame
        target_frame = ttk.LabelFrame(self.root, text="Target Configuration")
        target_frame.grid(row=2, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(4):
            target_frame.grid_columnconfigure(col, weight=1)

        ttk.Label(target_frame, text="Target IP:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.target_ip = tk.StringVar(value="")
        ttk.Entry(target_frame, textvariable=self.target_ip).grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(target_frame, text="Target Port:").grid(row=0, column=2, sticky="e", padx=5, pady=2)
        self.target_port = tk.IntVar(value=12345)
        ttk.Entry(target_frame, textvariable=self.target_port).grid(row=0, column=3, padx=5, pady=2, sticky="ew")

        # Packet Settings Frame
        packet_frame = ttk.LabelFrame(self.root, text="Packet Settings")
        packet_frame.grid(row=3, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(4):
            packet_frame.grid_columnconfigure(col, weight=1)

        ttk.Label(packet_frame, text="Packet Size (Bytes):").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.packet_size = tk.IntVar(value=512)  # Reduced default
        ttk.Entry(packet_frame, textvariable=self.packet_size).grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(packet_frame, text="Packets per Second:").grid(row=0, column=2, sticky="e", padx=5, pady=2)
        self.packets_per_second = tk.IntVar(value=100)  # Reduced default
        ttk.Entry(packet_frame, textvariable=self.packets_per_second).grid(row=0, column=3, padx=5, pady=2, sticky="ew")

        ttk.Label(packet_frame, text="Max Packets (0=Infinite):").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        self.max_packets = tk.IntVar(value=0)
        ttk.Entry(packet_frame, textvariable=self.max_packets).grid(row=1, column=1, padx=5, pady=2, sticky="ew")

        # Features Checkboxes Frame
        features_frame = ttk.LabelFrame(self.root, text="Features")
        features_frame.grid(row=4, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(4):
            features_frame.grid_columnconfigure(col, weight=1)

        # Fancy Checkboxes
        self.var_handshake = tk.BooleanVar()
        self.var_start_delay = tk.BooleanVar()
        self.var_verbose = tk.BooleanVar()

        handshake_chk = ttk.Checkbutton(features_frame, text="Enable Handshake",
                                        variable=self.var_handshake)
        handshake_chk.grid(row=0, column=0, sticky="w", padx=5, pady=2)

        delay_chk = ttk.Checkbutton(features_frame, text="Start Delay (3s)",
                                    variable=self.var_start_delay)
        delay_chk.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        verbose_chk = ttk.Checkbutton(features_frame, text="Verbose Logging",
                                      variable=self.var_verbose)
        verbose_chk.grid(row=0, column=2, sticky="w", padx=5, pady=2)

        # Additional Data Checkboxes
        self.var_timestamp = tk.BooleanVar()
        self.var_random = tk.BooleanVar()
        self.var_clientid = tk.BooleanVar()
        self.var_gps = tk.BooleanVar()

        timestamp_chk = ttk.Checkbutton(features_frame, text="Add Timestamp",
                                        variable=self.var_timestamp)
        timestamp_chk.grid(row=1, column=0, sticky="w", padx=5, pady=2)

        random_chk = ttk.Checkbutton(features_frame, text="Add Random Bytes",
                                     variable=self.var_random)
        random_chk.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        clientid_chk = ttk.Checkbutton(features_frame, text="Add Client ID",
                                       variable=self.var_clientid)
        clientid_chk.grid(row=1, column=2, sticky="w", padx=5, pady=2)

        gps_chk = ttk.Checkbutton(features_frame, text="Add GPS",
                                  variable=self.var_gps)
        gps_chk.grid(row=1, column=3, sticky="w", padx=5, pady=2)

        # Initialize var_autotune before creating the checkbox
        self.var_autotune = tk.BooleanVar(value=self.user_settings.get("autotune_enabled", True))

        # Autotune Checkbox
        autotune_chk = ttk.Checkbutton(features_frame, text="Enable Autotune",
                                       variable=self.var_autotune, command=self.toggle_autotune)
        autotune_chk.grid(row=2, column=0, sticky="w", padx=5, pady=2)

        # Counters Frame
        counters_frame = ttk.LabelFrame(self.root, text="Counters")
        counters_frame.grid(row=5, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(10):
            counters_frame.grid_columnconfigure(col, weight=1)

        ttk.Label(counters_frame, text="Sent Packets:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.sent_packet_label = ttk.Label(counters_frame, text="0")
        self.sent_packet_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(counters_frame, text="Received Packets:").grid(row=0, column=2, sticky="e", padx=5, pady=2)
        self.received_packet_label = ttk.Label(counters_frame, text="0")
        self.received_packet_label.grid(row=0, column=3, sticky="w", padx=5, pady=2)

        ttk.Label(counters_frame, text="Errors:").grid(row=0, column=4, sticky="e", padx=5, pady=2)
        self.error_label = ttk.Label(counters_frame, text="0")
        self.error_label.grid(row=0, column=5, sticky="w", padx=5, pady=2)

        ttk.Label(counters_frame, text="Lost Packets:").grid(row=0, column=6, sticky="e", padx=5, pady=2)
        self.lost_packet_label = ttk.Label(counters_frame, text="0")
        self.lost_packet_label.grid(row=0, column=7, sticky="w", padx=5, pady=2)

        # Current Speed Display Frame
        speed_frame = ttk.LabelFrame(self.root, text="Current Speed")
        speed_frame.grid(row=6, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(2):
            speed_frame.grid_columnconfigure(col, weight=1)

        ttk.Label(speed_frame, text="Speed:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.current_speed_label = ttk.Label(speed_frame, text="0 KB/s")
        self.current_speed_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        # Controls Frame
        controls_frame = ttk.Frame(self.root)
        controls_frame.grid(row=7, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(3):
            controls_frame.grid_columnconfigure(col, weight=1)

        # Buttons
        self.start_button = ttk.Button(controls_frame, text="Start", command=self.start_sending)
        self.start_button.grid(row=0, column=0, padx=5, pady=2, sticky="ew")

        self.stop_button = ttk.Button(controls_frame, text="Stop", command=self.stop_sending)
        self.stop_button.grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        self.clear_button = ttk.Button(controls_frame, text="Clear", command=self.clear_all)
        self.clear_button.grid(row=0, column=2, padx=5, pady=2, sticky="ew")

        # Status Label Frame
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=8, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(status_frame, textvariable=self.status_text).pack(anchor="w")

        # Debug Log Area Frame
        debug_frame = ttk.LabelFrame(self.root, text="Debug Log")
        debug_frame.grid(row=9, column=0, columnspan=10, padx=10, pady=5, sticky="nsew")
        debug_frame.grid_rowconfigure(0, weight=1)
        debug_frame.grid_columnconfigure(0, weight=1)

        self.debug_text = ScrolledText(debug_frame, state="disabled")
        self.debug_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

    def toggle_autotune(self):
        """Enable or disable autotune based on the checkbox."""
        if self.var_autotune.get():
            self.user_settings["autotune_enabled"] = True
            self.log("Autotune enabled.")
            self.start_autotune()
        else:
            self.user_settings["autotune_enabled"] = False
            self.log("Autotune disabled.")
            self.stop_autotune()

    def start_autotune(self):
        """Start the autotune thread."""
        if not self.autotune_running:
            self.autotune_running = True
            self.autotune_thread = threading.Thread(target=self.autotune_loop, daemon=True)
            self.autotune_thread.start()
            self.log("Autotune thread started.")

    def stop_autotune(self):
        """Stop the autotune thread."""
        if self.autotune_running:
            self.autotune_running = False
            self.log("Autotune thread stopped.")

    def autotune_loop(self):
        """Autotune loop that adjusts packet size and PPS based on packet loss."""
        interval = self.user_settings.get("autotune_interval", 5)
        loss_threshold_high = self.user_settings.get("autotune_loss_threshold_high", 5)
        loss_threshold_low = self.user_settings.get("autotune_loss_threshold_low", 2)
        packs_increment = self.user_settings.get("autotune_packs_increment", 10)
        packs_decrement = self.user_settings.get("autotune_packs_decrement", 10)
        size_increment = self.user_settings.get("autotune_size_increment", 1024)
        size_decrement = self.user_settings.get("autotune_size_decrement", 1024)
        max_packs = self.user_settings.get("max_packs_per_sec", 300)
        min_packs = self.user_settings.get("min_packs_per_sec", 10)
        max_size = self.user_settings.get("max_packet_size", 32768)
        min_size = self.user_settings.get("min_packet_size", 256)

        while self.autotune_running:
            time.sleep(interval)

            with self.lock:
                total_sent = self.packet_count
                total_lost = self.lost_packets

                if total_sent == 0:
                    self.log("Autotune: No packets sent in this interval.")
                    continue  # Avoid division by zero

                loss_rate = (total_lost / total_sent) * 100

                self.log(f"Autotune Check: {total_lost} lost out of {total_sent} packets. Loss Rate: {loss_rate:.2f}%")

                # Determine if adjustments are needed
                if loss_rate > loss_threshold_high:
                    self.log("Autotune: High loss rate detected. Reducing PPS and Packet Size.")
                    # Decrease PPS
                    current_pps = self.packets_per_second.get()
                    new_pps = max(min_packs, current_pps - packs_decrement)
                    if new_pps != current_pps:
                        self.packets_per_second.set(new_pps)
                        self.log(f"Autotune: Reducing PPS to {new_pps}.")
                    else:
                        self.log("Autotune: PPS already at minimum limit.")

                    # Decrease packet size
                    current_size = self.packet_size.get()
                    new_size = max(min_size, current_size - size_decrement)
                    if new_size != current_size:
                        self.packet_size.set(new_size)
                        self.log(f"Autotune: Reducing Packet Size to {new_size} bytes.")
                    else:
                        self.log("Autotune: Packet size already at minimum limit.")

                    # Reset counters
                    self.packet_count = 0
                    self.lost_packets = 0

                elif loss_rate < loss_threshold_low:
                    self.log("Autotune: Low loss rate detected. Increasing PPS and Packet Size.")
                    # Increase PPS
                    current_pps = self.packets_per_second.get()
                    new_pps = min(max_packs, current_pps + packs_increment)
                    if new_pps != current_pps:
                        self.packets_per_second.set(new_pps)
                        self.log(f"Autotune: Increasing PPS to {new_pps}.")
                    else:
                        self.log("Autotune: PPS already at maximum limit.")

                    # Increase packet size
                    current_size = self.packet_size.get()
                    new_size = min(max_size, current_size + size_increment)
                    if new_size != current_size:
                        self.packet_size.set(new_size)
                        self.log(f"Autotune: Increasing Packet Size to {new_size} bytes.")
                    else:
                        self.log("Autotune: Packet size already at maximum limit.")

                    # Reset counters
                    self.packet_count = 0
                    self.lost_packets = 0

                else:
                    self.log("Autotune: No adjustment needed this interval.")

    def auto_set_target_ip(self, *args):
        """Auto-copy the destination port IP into 'Target IP' if changed."""
        if self.destination_port.get():
            try:
                ip = self.destination_port.get().split(" - ")[1].strip()
                self.target_ip.set(ip)
                self.log(f"Auto-set Target IP to {ip} based on Destination Port selection.")
            except IndexError:
                pass

    def detect_network_ports(self):
        """Find all suitable IPv4 interfaces and store them in combos."""
        interfaces = psutil.net_if_addrs()
        available_ports = []
        for iface_name, iface_info in interfaces.items():
            lower_name = iface_name.lower()
            if any(x in lower_name for x in ["lo", "loopback", "wi-fi", "wireless", "wlan", "bluetooth"]):
                continue

            for addr in iface_info:
                if addr.family == socket.AF_INET:
                    if (addr.address.startswith("127.") or
                        addr.address.startswith("169.254.")):
                        continue
                    available_ports.append(f"{iface_name} - {addr.address}")

        self.source_port_combo["values"] = available_ports
        self.destination_port_combo["values"] = available_ports
        self.log("Detected interfaces: " + str(available_ports))

    def log(self, message):
        """Append messages to the GUI's ScrolledText widget with timestamps."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        self.debug_text.config(state="normal")
        self.debug_text.insert("end", full_message + "\n")
        self.debug_text.see("end")
        self.debug_text.config(state="disabled")

    def get_link_status(self, interface):
        """Return 'on' if interface is up, else 'off'."""
        stats = psutil.net_if_stats()
        if interface in stats and stats[interface].isup:
            return "on"
        return "off"

    def update_leds(self, canvas, status):
        """Set canvas to green if 'on', else gray."""
        canvas.config(bg="green" if status == "on" else "gray")

    def monitor_link_status(self):
        """Periodic check of link status for source & destination LEDs."""
        if self.source_port.get():
            name = self.source_port.get().split(" - ")[0]
            st = self.get_link_status(name)
            self.update_leds(self.source_link_led, st)
        if self.destination_port.get():
            name = self.destination_port.get().split(" - ")[0]
            st = self.get_link_status(name)
            self.update_leds(self.destination_link_led, st)

        self.root.after(1000, self.monitor_link_status)

    def start_sending(self):
        """'Start' button pressed: handshake/delay if needed, then send."""
        if self.running:
            self.log("Already running. Start command ignored.")
            return

        self.log("Start button pressed.")
        self.update_user_settings()

        # Check link statuses
        sp = self.source_port.get()
        if sp:
            s_iface = sp.split(" - ")[0]
            if self.get_link_status(s_iface) == "off":
                self.log(f"WARNING: Source interface '{sp}' appears DOWN.")
            else:
                self.log(f"Source interface '{sp}' is UP.")

        dp = self.destination_port.get()
        if dp:
            d_iface = dp.split(" - ")[0]
            if self.get_link_status(d_iface) == "off":
                self.log(f"WARNING: Destination interface '{dp}' appears DOWN.")
            else:
                self.log(f"Destination interface '{dp}' is UP.")

        # Stop old receiver, then start new if selected
        self.stop_receiver()
        if self.destination_port.get():
            self.start_packet_receiver()

        self.running = True
        self.status_text.set("Status: Sending...")

        # Check if we want a 3s start delay
        if self.var_start_delay.get():
            self.log("Delaying start by 3 seconds...")
            self.root.after(3000, self.do_pre_send_actions)
        else:
            self.do_pre_send_actions()

    def do_pre_send_actions(self):
        """If handshake is enabled, send it. Then proceed to 'send_packets'."""
        if not self.running:
            return

        if self.var_handshake.get():
            self.log("Sending a HELLO handshake packet...")
            self.send_handshake()

        self.send_packets()

    def send_handshake(self):
        """Send a single 'HELLO' packet to the target, ignoring seq logic."""
        sender_ip = "0.0.0.0"
        if self.source_port.get():
            try:
                sender_ip = self.source_port.get().split(" - ")[1].strip()
            except IndexError:
                pass

        target_ip = self.target_ip.get().strip()
        target_port = self.target_port.get()
        sock_hello = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock_hello.bind((sender_ip, 0))
            sock_hello.sendto(b"HELLO", (target_ip, target_port))
            self.log("Handshake packet (HELLO) sent.")
        except Exception as e:
            self.log(f"Error sending handshake: {e}")
        finally:
            sock_hello.close()

    def stop_sending(self):
        """Stop the sending process."""
        if self.running:
            self.log("Stop button pressed or send ended.")
        self.running = False
        if self.sock:
            self.log("Closing sender socket.")
            self.sock.close()
            self.sock = None
        self.status_text.set("Status: Stopped")

    def stop_receiver(self):
        """Close the receiving socket to end the receiver thread."""
        if self.recv_sock:
            self.log("Stopping receiver socket...")
            self.recv_sock.close()
            self.recv_sock = None

    def clear_all(self):
        """Reset everything, clear counters and debug text."""
        self.log("Clear button pressed. Resetting counters and debug log.")
        self.stop_sending()
        self.stop_receiver()

        with self.lock:
            self.packet_count = 0
            self.received_packet_count = 0
            self.error_count = 0
            self.lost_packets = 0

        self.bytes_sent_last_interval = 0  # Reset speed tracking

        self.sent_packet_label.config(text="0")
        self.received_packet_label.config(text="0")
        self.error_label.config(text="0")
        self.lost_packet_label.config(text="0")
        self.current_speed_label.config(text="0 KB/s")  # Reset speed display
        self.status_text.set("Status: Ready")

        self.debug_text.config(state="normal")
        self.debug_text.delete("1.0", tk.END)
        self.debug_text.config(state="disabled")

    def send_packets(self):
        """
        Create & bind the sending socket, then schedule sending packets
        at the chosen rate. We apply 'max_packets' if > 0. If 'Verbose' is on,
        log every packet.
        """
        sender_ip = "0.0.0.0"
        if self.source_port.get():
            try:
                sender_ip = self.source_port.get().split(" - ")[1].strip()
            except IndexError:
                pass

        target_ip = self.target_ip.get().strip()
        if not target_ip:
            self.log("Error: Target IP is empty. Cannot send packets.")
            self.status_text.set("Error: Target IP is empty.")
            self.running = False
            return

        target_port = self.target_port.get()
        pps = self.packets_per_second.get()
        if pps <= 0:
            pps = 1  # Prevent division by zero
        interval_ms = int(1000 / pps)
        max_pkts = self.max_packets.get()

        self.log(f"Source IP: {sender_ip}, Target IP: {target_ip}, "
                 f"Port: {target_port}, PPS: {pps}, Max Packets: {max_pkts}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.log(f"Binding sender socket to {sender_ip}:0 (ephemeral)...")
            self.sock.bind((sender_ip, 0))
            # Increase the send buffer size (e.g., to 1MB)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
            actual_send_buffer = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.log(f"Sender socket bound successfully with buffer size: {actual_send_buffer} bytes.")
        except Exception as e:
            self.log(f"Error binding sender socket: {e}")
            self.status_text.set(f"Error binding sender: {e}")
            self.running = False
            return

        def schedule_send():
            if not self.running:
                return

            with self.lock:
                if max_pkts > 0 and self.packet_count >= max_pkts:
                    self.log(f"Reached total send stop point ({max_pkts} packets). Stopping...")
                    self.stop_sending()
                    return

            try:
                packet = self.generate_packet(self.packet_count)
                bytes_sent = self.sock.sendto(packet, (target_ip, target_port))

                with self.lock:
                    self.packet_count += 1
                    current_count = self.packet_count
                    self.bytes_sent_last_interval += bytes_sent

                self.sent_packet_label.config(text=str(current_count))

                # Log every packet if verbose, else every 100th
                if self.var_verbose.get():
                    self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")
                else:
                    if current_count % 100 == 1:
                        self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")

                self.blink_led(self.source_link_led, self.source_port)

                # Schedule the next send
                self.root.after(interval_ms, schedule_send)

            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    current_error = self.error_count
                self.error_label.config(text=str(current_error))
                self.log(f"Send error: {e.__class__.__name__} - {e}")
                self.status_text.set(f"Send error: {e}")
                self.stop_sending()

        schedule_send()

    def generate_packet(self, seq_number):
        """
        Build the packet:
           [4-byte seq][(user_size - 8) 'X' bytes + optional data] + [4-byte CRC32]

        We clamp user_size to [0..65507]. Then, if any of the 4 "Add" checkboxes
        are checked, we append that data to the 'X' body before computing CRC32.
        """
        user_size = self.packet_size.get()
        if user_size < 0:
            user_size = 0
        if user_size > 65507:
            self.log(f"WARNING: Packet size {user_size} exceeds 65507. Clamping.")
            user_size = 65507

        # Base header = 4-byte seq
        seq_header = struct.pack("I", seq_number)

        # Reserve 8 bytes overhead (4 for seq, 4 for CRC32)
        base_body_size = max(0, user_size - 8)

        # Start with 'X' repeated base_body_size
        body = b"X" * base_body_size

        # Now conditionally append extra data from checkboxes
        # 1) Timestamp
        if self.var_timestamp.get():
            # E.g. "2023-08-25T14:10:35Z"
            now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            body += now_str.encode("utf-8")

        # 2) Random bytes (16 bytes)
        if self.var_random.get():
            rnd = os.urandom(16)
            body += rnd

        # 3) Client ID
        if self.var_clientid.get():
            body += b"CLIENT-XYZ"  # or you can store a user input if desired

        # 4) GPS
        if self.var_gps.get():
            # Example coordinate
            body += b"GPS:37.7749,-122.4194"

        # Now compute CRC32
        full_payload = seq_header + body
        chksum = struct.pack("I", zlib.crc32(full_payload) & 0xFFFFFFFF)
        return full_payload + chksum

    def verify_packet(self, data):
        """
        Check CRC32, parse seq_number. If valid, track lost packets.
        """
        if len(data) < 8:
            self.log(f"Received packet too short: {len(data)} bytes.")
            return False

        payload = data[:-4]
        received_crc = struct.unpack("I", data[-4:])[0]
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if calc_crc != received_crc:
            self.log(f"CRC mismatch: calculated {calc_crc}, received {received_crc}.")
            return False

        seq = struct.unpack("I", payload[:4])[0]
        if seq > self.last_received_seq:
            gap = seq - (self.last_received_seq + 1)
            if gap > 0:
                with self.lock:
                    self.lost_packets += gap
                self.log(f"Detected {gap} lost packet(s).")
            self.last_received_seq = seq
            self.lost_packet_label.config(text=str(self.lost_packets))

        return True

    def start_packet_receiver(self):
        """Launch a receiver thread if a destination port is chosen."""
        if not self.destination_port.get():
            self.log("No destination interface selected; skipping receiver setup.")
            return

        self.log("Starting receiver thread...")
        self.receiver_thread = threading.Thread(target=self.receive_packets, daemon=True)
        self.receiver_thread.start()

    def receive_packets(self):
        """
        Bind and receive packets in a loop. If verified, increment 'received_packet_count'.
        """
        try:
            if self.destination_port.get():
                recv_ip = self.destination_port.get().split(" - ")[1].strip()
            else:
                recv_ip = "0.0.0.0"

            recv_port = self.target_port.get()
            self.log(f"Receiver binding to {recv_ip}:{recv_port}...")

            self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase the receive buffer size (e.g., to 1MB)
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

            actual_buffer_size = self.recv_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log(f"Receiver socket bound successfully with buffer size: {actual_buffer_size} bytes.")

            self.recv_sock.settimeout(2)
            self.recv_sock.bind((recv_ip, recv_port))

            self.log("Receiver socket bound. Listening for packets...")

            while True:
                try:
                    data, addr = self.recv_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    self.log("Receiver socket closed, exiting thread.")
                    break
                except Exception as e:
                    self.log(f"Receiver thread unexpected error: {e.__class__.__name__} - {e}")
                    with self.lock:
                        self.error_count += 1
                    self.error_label.config(text=str(self.error_count))
                    continue

                # If packet verifies, increment received
                if self.verify_packet(data):
                    with self.lock:
                        self.received_packet_count += 1
                        current_received = self.received_packet_count
                    self.received_packet_label.config(text=str(current_received))
                else:
                    with self.lock:
                        self.error_count += 1
                        current_error = self.error_count
                    self.error_label.config(text=str(current_error))

                self.blink_led(self.destination_link_led, self.destination_port)

        except Exception as e:
            self.log(f"Receiver thread error: {e} - {traceback.format_exc()}")

    def blink_led(self, canvas, port_var):
        """Blink LED to yellow, then revert to green/gray."""
        iface_name = None
        if port_var.get():
            iface_name = port_var.get().split(" - ")[0]

        baseline_color = "gray"
        if iface_name:
            stats = psutil.net_if_stats()
            if iface_name in stats and stats[iface_name].isup:
                baseline_color = "green"

        canvas.config(bg="yellow")
        self.root.after(100, lambda: canvas.config(bg=baseline_color))

    def check_receive_activity(self):
        """Warn if no new packets arrived since last check, else OK."""
        if self.running and self.destination_port.get():
            if self.received_packet_count == self.last_received_check_count:
                self.status_text.set("Warning: No new packets received.")
            else:
                self.status_text.set("Status: Receiving OK")

        self.last_received_check_count = self.received_packet_count
        self.root.after(2000, self.check_receive_activity)

    def update_speed(self):
        """Calculate and update the current speed display every second."""
        bytes_sent = self.bytes_sent_last_interval
        # Convert bytes to KB/s or MB/s
        speed_kb = bytes_sent / 1024
        if speed_kb < 1024:
            speed = f"{speed_kb:.2f} KB/s"
        else:
            speed_mb = speed_kb / 1024
            speed = f"{speed_mb:.2f} MB/s"
        self.current_speed_label.config(text=speed)
        # Reset the counter
        self.bytes_sent_last_interval = 0
        # Schedule the next speed update after 1 second
        self.root.after(1000, self.update_speed)

    def send_packets(self):
        """
        Create & bind the sending socket, then schedule sending packets
        at the chosen rate. We apply 'max_packets' if > 0. If 'Verbose' is on,
        log every packet.
        """
        sender_ip = "0.0.0.0"
        if self.source_port.get():
            try:
                sender_ip = self.source_port.get().split(" - ")[1].strip()
            except IndexError:
                pass

        target_ip = self.target_ip.get().strip()
        if not target_ip:
            self.log("Error: Target IP is empty. Cannot send packets.")
            self.status_text.set("Error: Target IP is empty.")
            self.running = False
            return

        target_port = self.target_port.get()
        pps = self.packets_per_second.get()
        if pps <= 0:
            pps = 1  # Prevent division by zero
        interval_ms = int(1000 / pps)
        max_pkts = self.max_packets.get()

        self.log(f"Source IP: {sender_ip}, Target IP: {target_ip}, "
                 f"Port: {target_port}, PPS: {pps}, Max Packets: {max_pkts}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.log(f"Binding sender socket to {sender_ip}:0 (ephemeral)...")
            self.sock.bind((sender_ip, 0))
            # Increase the send buffer size (e.g., to 1MB)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
            actual_send_buffer = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.log(f"Sender socket bound successfully with buffer size: {actual_send_buffer} bytes.")
        except Exception as e:
            self.log(f"Error binding sender socket: {e}")
            self.status_text.set(f"Error binding sender: {e}")
            self.running = False
            return

        def schedule_send():
            if not self.running:
                return

            with self.lock:
                if max_pkts > 0 and self.packet_count >= max_pkts:
                    self.log(f"Reached total send stop point ({max_pkts} packets). Stopping...")
                    self.stop_sending()
                    return

            try:
                packet = self.generate_packet(self.packet_count)
                bytes_sent = self.sock.sendto(packet, (target_ip, target_port))

                with self.lock:
                    self.packet_count += 1
                    current_count = self.packet_count
                    self.bytes_sent_last_interval += bytes_sent

                self.sent_packet_label.config(text=str(current_count))

                # Log every packet if verbose, else every 100th
                if self.var_verbose.get():
                    self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")
                else:
                    if current_count % 100 == 1:
                        self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")

                self.blink_led(self.source_link_led, self.source_port)

                # Schedule the next send
                self.root.after(interval_ms, schedule_send)

            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    current_error = self.error_count
                self.error_label.config(text=str(current_error))
                self.log(f"Send error: {e.__class__.__name__} - {e}")
                self.status_text.set(f"Send error: {e}")
                self.stop_sending()

        schedule_send()

    def generate_packet(self, seq_number):
        """
        Build the packet:
           [4-byte seq][(user_size - 8) 'X' bytes + optional data] + [4-byte CRC32]

        We clamp user_size to [0..65507]. Then, if any of the 4 "Add" checkboxes
        are checked, we append that data to the 'X' body before computing CRC32.
        """
        user_size = self.packet_size.get()
        if user_size < 0:
            user_size = 0
        if user_size > 65507:
            self.log(f"WARNING: Packet size {user_size} exceeds 65507. Clamping.")
            user_size = 65507

        # Base header = 4-byte seq
        seq_header = struct.pack("I", seq_number)

        # Reserve 8 bytes overhead (4 for seq, 4 for CRC32)
        base_body_size = max(0, user_size - 8)

        # Start with 'X' repeated base_body_size
        body = b"X" * base_body_size

        # Now conditionally append extra data from checkboxes
        # 1) Timestamp
        if self.var_timestamp.get():
            # E.g. "2023-08-25T14:10:35Z"
            now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            body += now_str.encode("utf-8")

        # 2) Random bytes (16 bytes)
        if self.var_random.get():
            rnd = os.urandom(16)
            body += rnd

        # 3) Client ID
        if self.var_clientid.get():
            body += b"CLIENT-XYZ"  # or you can store a user input if desired

        # 4) GPS
        if self.var_gps.get():
            # Example coordinate
            body += b"GPS:37.7749,-122.4194"

        # Now compute CRC32
        full_payload = seq_header + body
        chksum = struct.pack("I", zlib.crc32(full_payload) & 0xFFFFFFFF)
        return full_payload + chksum

    def verify_packet(self, data):
        """
        Check CRC32, parse seq_number. If valid, track lost packets.
        """
        if len(data) < 8:
            self.log(f"Received packet too short: {len(data)} bytes.")
            return False

        payload = data[:-4]
        received_crc = struct.unpack("I", data[-4:])[0]
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if calc_crc != received_crc:
            self.log(f"CRC mismatch: calculated {calc_crc}, received {received_crc}.")
            return False

        seq = struct.unpack("I", payload[:4])[0]
        if seq > self.last_received_seq:
            gap = seq - (self.last_received_seq + 1)
            if gap > 0:
                with self.lock:
                    self.lost_packets += gap
                self.log(f"Detected {gap} lost packet(s).")
            self.last_received_seq = seq
            self.lost_packet_label.config(text=str(self.lost_packets))

        return True

    def start_packet_receiver(self):
        """Launch a receiver thread if a destination port is chosen."""
        if not self.destination_port.get():
            self.log("No destination interface selected; skipping receiver setup.")
            return

        self.log("Starting receiver thread...")
        self.receiver_thread = threading.Thread(target=self.receive_packets, daemon=True)
        self.receiver_thread.start()

    def receive_packets(self):
        """
        Bind and receive packets in a loop. If verified, increment 'received_packet_count'.
        """
        try:
            if self.destination_port.get():
                recv_ip = self.destination_port.get().split(" - ")[1].strip()
            else:
                recv_ip = "0.0.0.0"

            recv_port = self.target_port.get()
            self.log(f"Receiver binding to {recv_ip}:{recv_port}...")

            self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase the receive buffer size (e.g., to 1MB)
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

            actual_buffer_size = self.recv_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log(f"Receiver socket bound successfully with buffer size: {actual_buffer_size} bytes.")

            self.recv_sock.settimeout(2)
            self.recv_sock.bind((recv_ip, recv_port))

            self.log("Receiver socket bound. Listening for packets...")

            while True:
                try:
                    data, addr = self.recv_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    self.log("Receiver socket closed, exiting thread.")
                    break
                except Exception as e:
                    self.log(f"Receiver thread unexpected error: {e.__class__.__name__} - {e}")
                    with self.lock:
                        self.error_count += 1
                    self.error_label.config(text=str(self.error_count))
                    continue

                # If packet verifies, increment received
                if self.verify_packet(data):
                    with self.lock:
                        self.received_packet_count += 1
                        current_received = self.received_packet_count
                    self.received_packet_label.config(text=str(current_received))
                else:
                    with self.lock:
                        self.error_count += 1
                        current_error = self.error_count
                    self.error_label.config(text=str(current_error))

                self.blink_led(self.destination_link_led, self.destination_port)

        except Exception as e:
            self.log(f"Receiver thread error: {e} - {traceback.format_exc()}")

    def blink_led(self, canvas, port_var):
        """Blink LED to yellow, then revert to green/gray."""
        iface_name = None
        if port_var.get():
            iface_name = port_var.get().split(" - ")[0]

        baseline_color = "gray"
        if iface_name:
            stats = psutil.net_if_stats()
            if iface_name in stats and stats[iface_name].isup:
                baseline_color = "green"

        canvas.config(bg="yellow")
        self.root.after(100, lambda: canvas.config(bg=baseline_color))

    def check_receive_activity(self):
        """Warn if no new packets arrived since last check, else OK."""
        if self.running and self.destination_port.get():
            if self.received_packet_count == self.last_received_check_count:
                self.status_text.set("Warning: No new packets received.")
            else:
                self.status_text.set("Status: Receiving OK")

        self.last_received_check_count = self.received_packet_count
        self.root.after(2000, self.check_receive_activity)

    def update_speed(self):
        """Calculate and update the current speed display every second."""
        bytes_sent = self.bytes_sent_last_interval
        # Convert bytes to KB/s or MB/s
        speed_kb = bytes_sent / 1024
        if speed_kb < 1024:
            speed = f"{speed_kb:.2f} KB/s"
        else:
            speed_mb = speed_kb / 1024
            speed = f"{speed_mb:.2f} MB/s"
        self.current_speed_label.config(text=speed)
        # Reset the counter
        self.bytes_sent_last_interval = 0
        # Schedule the next speed update after 1 second
        self.root.after(1000, self.update_speed)

    def send_packets(self):
        """
        Create & bind the sending socket, then schedule sending packets
        at the chosen rate. We apply 'max_packets' if > 0. If 'Verbose' is on,
        log every packet.
        """
        sender_ip = "0.0.0.0"
        if self.source_port.get():
            try:
                sender_ip = self.source_port.get().split(" - ")[1].strip()
            except IndexError:
                pass

        target_ip = self.target_ip.get().strip()
        if not target_ip:
            self.log("Error: Target IP is empty. Cannot send packets.")
            self.status_text.set("Error: Target IP is empty.")
            self.running = False
            return

        target_port = self.target_port.get()
        pps = self.packets_per_second.get()
        if pps <= 0:
            pps = 1  # Prevent division by zero
        interval_ms = int(1000 / pps)
        max_pkts = self.max_packets.get()

        self.log(f"Source IP: {sender_ip}, Target IP: {target_ip}, "
                 f"Port: {target_port}, PPS: {pps}, Max Packets: {max_pkts}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.log(f"Binding sender socket to {sender_ip}:0 (ephemeral)...")
            self.sock.bind((sender_ip, 0))
            # Increase the send buffer size (e.g., to 1MB)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
            actual_send_buffer = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.log(f"Sender socket bound successfully with buffer size: {actual_send_buffer} bytes.")
        except Exception as e:
            self.log(f"Error binding sender socket: {e}")
            self.status_text.set(f"Error binding sender: {e}")
            self.running = False
            return

        def schedule_send():
            if not self.running:
                return

            with self.lock:
                if max_pkts > 0 and self.packet_count >= max_pkts:
                    self.log(f"Reached total send stop point ({max_pkts} packets). Stopping...")
                    self.stop_sending()
                    return

            try:
                packet = self.generate_packet(self.packet_count)
                bytes_sent = self.sock.sendto(packet, (target_ip, target_port))

                with self.lock:
                    self.packet_count += 1
                    current_count = self.packet_count
                    self.bytes_sent_last_interval += bytes_sent

                self.sent_packet_label.config(text=str(current_count))

                # Log every packet if verbose, else every 100th
                if self.var_verbose.get():
                    self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")
                else:
                    if current_count % 100 == 1:
                        self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")

                self.blink_led(self.source_link_led, self.source_port)

                # Schedule the next send
                self.root.after(interval_ms, schedule_send)

            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    current_error = self.error_count
                self.error_label.config(text=str(current_error))
                self.log(f"Send error: {e.__class__.__name__} - {e}")
                self.status_text.set(f"Send error: {e}")
                self.stop_sending()

        schedule_send()

    def generate_packet(self, seq_number):
        """
        Build the packet:
           [4-byte seq][(user_size - 8) 'X' bytes + optional data] + [4-byte CRC32]

        We clamp user_size to [0..65507]. Then, if any of the 4 "Add" checkboxes
        are checked, we append that data to the 'X' body before computing CRC32.
        """
        user_size = self.packet_size.get()
        if user_size < 0:
            user_size = 0
        if user_size > 65507:
            self.log(f"WARNING: Packet size {user_size} exceeds 65507. Clamping.")
            user_size = 65507

        # Base header = 4-byte seq
        seq_header = struct.pack("I", seq_number)

        # Reserve 8 bytes overhead (4 for seq, 4 for CRC32)
        base_body_size = max(0, user_size - 8)

        # Start with 'X' repeated base_body_size
        body = b"X" * base_body_size

        # Now conditionally append extra data from checkboxes
        # 1) Timestamp
        if self.var_timestamp.get():
            # E.g. "2023-08-25T14:10:35Z"
            now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            body += now_str.encode("utf-8")

        # 2) Random bytes (16 bytes)
        if self.var_random.get():
            rnd = os.urandom(16)
            body += rnd

        # 3) Client ID
        if self.var_clientid.get():
            body += b"CLIENT-XYZ"  # or you can store a user input if desired

        # 4) GPS
        if self.var_gps.get():
            # Example coordinate
            body += b"GPS:37.7749,-122.4194"

        # Now compute CRC32
        full_payload = seq_header + body
        chksum = struct.pack("I", zlib.crc32(full_payload) & 0xFFFFFFFF)
        return full_payload + chksum

    def verify_packet(self, data):
        """
        Check CRC32, parse seq_number. If valid, track lost packets.
        """
        if len(data) < 8:
            self.log(f"Received packet too short: {len(data)} bytes.")
            return False

        payload = data[:-4]
        received_crc = struct.unpack("I", data[-4:])[0]
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if calc_crc != received_crc:
            self.log(f"CRC mismatch: calculated {calc_crc}, received {received_crc}.")
            return False

        seq = struct.unpack("I", payload[:4])[0]
        if seq > self.last_received_seq:
            gap = seq - (self.last_received_seq + 1)
            if gap > 0:
                with self.lock:
                    self.lost_packets += gap
                self.log(f"Detected {gap} lost packet(s).")
            self.last_received_seq = seq
            self.lost_packet_label.config(text=str(self.lost_packets))

        return True

    def start_packet_receiver(self):
        """Launch a receiver thread if a destination port is chosen."""
        if not self.destination_port.get():
            self.log("No destination interface selected; skipping receiver setup.")
            return

        self.log("Starting receiver thread...")
        self.receiver_thread = threading.Thread(target=self.receive_packets, daemon=True)
        self.receiver_thread.start()

    def receive_packets(self):
        """
        Bind and receive packets in a loop. If verified, increment 'received_packet_count'.
        """
        try:
            if self.destination_port.get():
                recv_ip = self.destination_port.get().split(" - ")[1].strip()
            else:
                recv_ip = "0.0.0.0"

            recv_port = self.target_port.get()
            self.log(f"Receiver binding to {recv_ip}:{recv_port}...")

            self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase the receive buffer size (e.g., to 1MB)
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

            actual_buffer_size = self.recv_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log(f"Receiver socket bound successfully with buffer size: {actual_buffer_size} bytes.")

            self.recv_sock.settimeout(2)
            self.recv_sock.bind((recv_ip, recv_port))

            self.log("Receiver socket bound. Listening for packets...")

            while True:
                try:
                    data, addr = self.recv_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    self.log("Receiver socket closed, exiting thread.")
                    break
                except Exception as e:
                    self.log(f"Receiver thread unexpected error: {e.__class__.__name__} - {e}")
                    with self.lock:
                        self.error_count += 1
                    self.error_label.config(text=str(self.error_count))
                    continue

                # If packet verifies, increment received
                if self.verify_packet(data):
                    with self.lock:
                        self.received_packet_count += 1
                        current_received = self.received_packet_count
                    self.received_packet_label.config(text=str(current_received))
                else:
                    with self.lock:
                        self.error_count += 1
                        current_error = self.error_count
                    self.error_label.config(text=str(current_error))

                self.blink_led(self.destination_link_led, self.destination_port)

        except Exception as e:
            self.log(f"Receiver thread error: {e} - {traceback.format_exc()}")

    def blink_led(self, canvas, port_var):
        """Blink LED to yellow, then revert to green/gray."""
        iface_name = None
        if port_var.get():
            iface_name = port_var.get().split(" - ")[0]

        baseline_color = "gray"
        if iface_name:
            stats = psutil.net_if_stats()
            if iface_name in stats and stats[iface_name].isup:
                baseline_color = "green"

        canvas.config(bg="yellow")
        self.root.after(100, lambda: canvas.config(bg=baseline_color))

    def check_receive_activity(self):
        """Warn if no new packets arrived since last check, else OK."""
        if self.running and self.destination_port.get():
            if self.received_packet_count == self.last_received_check_count:
                self.status_text.set("Warning: No new packets received.")
            else:
                self.status_text.set("Status: Receiving OK")

        self.last_received_check_count = self.received_packet_count
        self.root.after(2000, self.check_receive_activity)

    def update_speed(self):
        """Calculate and update the current speed display every second."""
        bytes_sent = self.bytes_sent_last_interval
        # Convert bytes to KB/s or MB/s
        speed_kb = bytes_sent / 1024
        if speed_kb < 1024:
            speed = f"{speed_kb:.2f} KB/s"
        else:
            speed_mb = speed_kb / 1024
            speed = f"{speed_mb:.2f} MB/s"
        self.current_speed_label.config(text=speed)
        # Reset the counter
        self.bytes_sent_last_interval = 0
        # Schedule the next speed update after 1 second
        self.root.after(1000, self.update_speed)

    def send_packets(self):
        """
        Create & bind the sending socket, then schedule sending packets
        at the chosen rate. We apply 'max_packets' if > 0. If 'Verbose' is on,
        log every packet.
        """
        sender_ip = "0.0.0.0"
        if self.source_port.get():
            try:
                sender_ip = self.source_port.get().split(" - ")[1].strip()
            except IndexError:
                pass

        target_ip = self.target_ip.get().strip()
        if not target_ip:
            self.log("Error: Target IP is empty. Cannot send packets.")
            self.status_text.set("Error: Target IP is empty.")
            self.running = False
            return

        target_port = self.target_port.get()
        pps = self.packets_per_second.get()
        if pps <= 0:
            pps = 1  # Prevent division by zero
        interval_ms = int(1000 / pps)
        max_pkts = self.max_packets.get()

        self.log(f"Source IP: {sender_ip}, Target IP: {target_ip}, "
                 f"Port: {target_port}, PPS: {pps}, Max Packets: {max_pkts}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.log(f"Binding sender socket to {sender_ip}:0 (ephemeral)...")
            self.sock.bind((sender_ip, 0))
            # Increase the send buffer size (e.g., to 1MB)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
            actual_send_buffer = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.log(f"Sender socket bound successfully with buffer size: {actual_send_buffer} bytes.")
        except Exception as e:
            self.log(f"Error binding sender socket: {e}")
            self.status_text.set(f"Error binding sender: {e}")
            self.running = False
            return

        def schedule_send():
            if not self.running:
                return

            with self.lock:
                if max_pkts > 0 and self.packet_count >= max_pkts:
                    self.log(f"Reached total send stop point ({max_pkts} packets). Stopping...")
                    self.stop_sending()
                    return

            try:
                packet = self.generate_packet(self.packet_count)
                bytes_sent = self.sock.sendto(packet, (target_ip, target_port))

                with self.lock:
                    self.packet_count += 1
                    current_count = self.packet_count
                    self.bytes_sent_last_interval += bytes_sent

                self.sent_packet_label.config(text=str(current_count))

                # Log every packet if verbose, else every 100th
                if self.var_verbose.get():
                    self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")
                else:
                    if current_count % 100 == 1:
                        self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")

                self.blink_led(self.source_link_led, self.source_port)

                # Schedule the next send
                self.root.after(interval_ms, schedule_send)

            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    current_error = self.error_count
                self.error_label.config(text=str(current_error))
                self.log(f"Send error: {e.__class__.__name__} - {e}")
                self.status_text.set(f"Send error: {e}")
                self.stop_sending()

        schedule_send()

# Entry point
if __name__ == "__main__":
    root = tk.Tk()
    # Allow window to be resizable
    root.resizable(True, True)
    app = PacketGeneratorApp(root)
    root.mainloop()
