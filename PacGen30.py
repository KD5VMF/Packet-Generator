import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import socket
import psutil
import time
import struct
import json
import os
import datetime
import zlib
import traceback
import sys
import uuid
import binascii

# Configuration file for persistent settings
CONFIG_FILE = "packet_gen_config.json"

class PacketGeneratorApp:
    """
    A Packet Generator with enterprise-level features:
      - Persistent settings in JSON
      - Enhanced checkboxes (protocol version, source MAC, unique ID, payload signature)
      - Lost packet tracking via sequence numbers and interface status
      - Automatic stop at a max packet count
      - Link LEDs and a resizable GUI window
      - Autotune feature to adjust packet size and packets per second based on packet loss
      - Real-time speed display (KB/s, MB/s, Mbps)
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Packet Generator (Enterprise)")
        self.root.geometry("1200x800")  # Set a reasonable default size

        # State / Counters
        self.running = False
        self.packet_count = 0
        self.received_packet_count = 0
        self.error_count = 0

        # Lost-packet tracking
        # Use two counters: one cumulative (lost_packets_total) for display and one interval (lost_packets_interval) for autotuning.
        self.lost_packets_total = 0
        self.lost_packets_interval = 0
        self.last_received_seq = -1

        # Timestamp for last received packet
        self.last_packet_received_time = time.perf_counter()

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
            "packet_size": 32768,  # Starting at 32768 bytes
            "packets_per_second": 1000,  # Starting at 1000 PPS
            "max_packets": 0,  # 0 => infinite
            # Enhanced checkboxes
            "use_handshake": False,
            "use_start_delay": False,
            "use_verbose": False,
            "add_protocol_version": False,
            "add_source_mac": False,
            "add_unique_id": False,
            "add_payload_signature": False,
            # Autotune settings
            "autotune_enabled": True,
            "autotune_interval": 5,  # seconds
            "autotune_packs_increment": 50,    # packets per second (step size)
            "autotune_packs_decrement": 50,    # packets per second (step size)
            "autotune_size_increment": 500,    # bytes (step size)
            "autotune_size_decrement": 500,    # bytes (step size)
            "max_packet_size": 32768,           # Maximum packet size
            "max_packs_per_sec": 5000,          # Maximum packets per second
            "min_packs_per_sec": 50,            # Minimum packets per second
            "min_packet_size": 5000,            # Minimum packet size
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
        try:
            if sys.platform.startswith('win'):
                self.root.state('zoomed')
            elif sys.platform.startswith('darwin'):
                self.root.attributes('-zoomed', True)
            else:
                self.root.state('zoomed')  # Changed to 'zoomed' for consistency
        except:
            pass  # If maximizing fails, continue without it

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

        self.user_settings["add_protocol_version"] = bool(self.var_protocol_version.get())
        self.user_settings["add_source_mac"] = bool(self.var_source_mac.get())
        self.user_settings["add_unique_id"] = bool(self.var_unique_id.get())
        self.user_settings["add_payload_signature"] = bool(self.var_payload_signature.get())

        # Autotune settings
        self.user_settings["autotune_enabled"] = bool(self.var_autotune.get())

    def apply_loaded_settings(self):
        """Set combos, entries, checkboxes from user_settings."""
        source_vals = self.source_port_combo["values"]
        destination_vals = self.destination_port_combo["values"]

        if self.user_settings["source_port"] in source_vals:
            self.source_port.set(self.user_settings["source_port"])
        else:
            self.source_port.set('')  # Reset if not found

        if self.user_settings["destination_port"] in destination_vals:
            self.destination_port.set(self.user_settings["destination_port"])
        else:
            self.destination_port.set('')  # Reset if not found

        self.target_ip.set(self.user_settings["target_ip"])
        self.target_port.set(self.user_settings["target_port"])
        self.packet_size.set(self.user_settings["packet_size"])
        self.packets_per_second.set(self.user_settings["packets_per_second"])
        self.max_packets.set(self.user_settings["max_packets"])

        self.var_handshake.set(self.user_settings["use_handshake"])
        self.var_start_delay.set(self.user_settings["use_start_delay"])
        self.var_verbose.set(self.user_settings["use_verbose"])

        self.var_protocol_version.set(self.user_settings["add_protocol_version"])
        self.var_source_mac.set(self.user_settings["add_source_mac"])
        self.var_unique_id.set(self.user_settings["add_unique_id"])
        self.var_payload_signature.set(self.user_settings["add_payload_signature"])

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
        ttk.Label(title_frame, text="Packet Generator", font=("Helvetica", 24, "bold")).pack(fill='x', padx=10)

        # Network Configuration Frame
        net_config_frame = ttk.LabelFrame(self.root, text="Network Configuration")
        net_config_frame.grid(row=1, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(8):
            net_config_frame.grid_columnconfigure(col, weight=1)

        # Source Port
        ttk.Label(net_config_frame, text="Select Source Port:", anchor="e").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.source_port = tk.StringVar()
        self.source_port_combo = ttk.Combobox(net_config_frame, textvariable=self.source_port,
                                             state="readonly")
        self.source_port_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Destination Port
        ttk.Label(net_config_frame, text="Select Destination Port:", anchor="e").grid(row=0, column=2, sticky="e", padx=5, pady=5)
        self.destination_port = tk.StringVar()
        self.destination_port.trace("w", self.auto_set_target_ip)
        self.destination_port_combo = ttk.Combobox(net_config_frame, textvariable=self.destination_port,
                                                 state="readonly")
        self.destination_port_combo.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        # Source Link LED
        ttk.Label(net_config_frame, text="Source Link:", anchor="e").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.source_link_led = tk.Canvas(net_config_frame, width=20, height=20, bg="gray")
        self.source_link_led.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Destination Link LED
        ttk.Label(net_config_frame, text="Destination Link:", anchor="e").grid(row=1, column=2, sticky="e", padx=5, pady=5)
        self.destination_link_led = tk.Canvas(net_config_frame, width=20, height=20, bg="gray")
        self.destination_link_led.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        # Target Configuration Frame
        target_frame = ttk.LabelFrame(self.root, text="Target Configuration")
        target_frame.grid(row=2, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(8):
            target_frame.grid_columnconfigure(col, weight=1)

        # Target IP
        ttk.Label(target_frame, text="Target IP:", anchor="e").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.target_ip = tk.StringVar(value="")
        self.target_ip_entry = ttk.Entry(target_frame, textvariable=self.target_ip, state='readonly')
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Target Port
        ttk.Label(target_frame, text="Target Port:", anchor="e").grid(row=0, column=2, sticky="e", padx=5, pady=5)
        self.target_port = tk.IntVar(value=12345)
        self.target_port_entry = ttk.Entry(target_frame, textvariable=self.target_port)
        self.target_port_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        # Packet Settings Frame
        packet_frame = ttk.LabelFrame(self.root, text="Packet Settings")
        packet_frame.grid(row=3, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(8):
            packet_frame.grid_columnconfigure(col, weight=1)

        # Packet Size
        ttk.Label(packet_frame, text="Packet Size (Bytes):", anchor="e").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.packet_size = tk.IntVar(value=32768)  # Starting at 32768 bytes
        self.packet_size_entry = ttk.Entry(packet_frame, textvariable=self.packet_size)
        self.packet_size_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Packets per Second
        ttk.Label(packet_frame, text="Packets per Second:", anchor="e").grid(row=0, column=2, sticky="e", padx=5, pady=5)
        self.packets_per_second = tk.IntVar(value=1000)  # Starting at 1000 PPS
        self.packets_per_second_entry = ttk.Entry(packet_frame, textvariable=self.packets_per_second)
        self.packets_per_second_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        # Max Packets
        ttk.Label(packet_frame, text="Max Packets (0=Infinite):", anchor="e").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.max_packets = tk.IntVar(value=0)
        self.max_packets_entry = ttk.Entry(packet_frame, textvariable=self.max_packets)
        self.max_packets_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Features Checkboxes Frame
        features_frame = ttk.LabelFrame(self.root, text="Features")
        features_frame.grid(row=4, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(8):
            features_frame.grid_columnconfigure(col, weight=1)

        # Enhanced Checkboxes
        self.var_handshake = tk.BooleanVar()
        self.var_start_delay = tk.BooleanVar()
        self.var_verbose = tk.BooleanVar()

        self.handshake_chk = ttk.Checkbutton(features_frame, text="Enable Handshake",
                                        variable=self.var_handshake)
        self.handshake_chk.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.delay_chk = ttk.Checkbutton(features_frame, text="Start Delay (3s)",
                                    variable=self.var_start_delay)
        self.delay_chk.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        self.verbose_chk = ttk.Checkbutton(features_frame, text="Verbose Logging",
                                      variable=self.var_verbose)
        self.verbose_chk.grid(row=0, column=2, sticky="w", padx=5, pady=5)

        # Enhanced Data Checkboxes
        self.var_protocol_version = tk.BooleanVar()
        self.var_source_mac = tk.BooleanVar()
        self.var_unique_id = tk.BooleanVar()
        self.var_payload_signature = tk.BooleanVar()

        self.protocol_version_chk = ttk.Checkbutton(features_frame, text="Add Protocol Version",
                                               variable=self.var_protocol_version)
        self.protocol_version_chk.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        self.source_mac_chk = ttk.Checkbutton(features_frame, text="Add Source MAC Address",
                                         variable=self.var_source_mac)
        self.source_mac_chk.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        self.unique_id_chk = ttk.Checkbutton(features_frame, text="Add Unique Identifier",
                                        variable=self.var_unique_id)
        self.unique_id_chk.grid(row=1, column=2, sticky="w", padx=5, pady=5)

        self.payload_signature_chk = ttk.Checkbutton(features_frame, text="Add Payload Signature",
                                                variable=self.var_payload_signature)
        self.payload_signature_chk.grid(row=1, column=3, sticky="w", padx=5, pady=5)

        # Autotune Checkbox
        self.var_autotune = tk.BooleanVar(value=self.user_settings.get("autotune_enabled", True))
        self.autotune_chk = ttk.Checkbutton(features_frame, text="Enable Autotune",
                                       variable=self.var_autotune, command=self.toggle_autotune)
        self.autotune_chk.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        # Counters Frame
        counters_frame = ttk.LabelFrame(self.root, text="Counters")
        counters_frame.grid(row=5, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(8):
            counters_frame.grid_columnconfigure(col, weight=1)

        # Sent Packets
        ttk.Label(counters_frame, text="Sent Packets:", anchor="e").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.sent_packet_label = ttk.Label(counters_frame, text="0")
        self.sent_packet_label.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # Received Packets
        ttk.Label(counters_frame, text="Received Packets:", anchor="e").grid(row=0, column=2, sticky="e", padx=5, pady=5)
        self.received_packet_label = ttk.Label(counters_frame, text="0")
        self.received_packet_label.grid(row=0, column=3, sticky="w", padx=5, pady=5)

        # Errors
        ttk.Label(counters_frame, text="Errors:", anchor="e").grid(row=0, column=4, sticky="e", padx=5, pady=5)
        self.error_label = ttk.Label(counters_frame, text="0")
        self.error_label.grid(row=0, column=5, sticky="w", padx=5, pady=5)

        # Lost Packets
        ttk.Label(counters_frame, text="Lost Packets:", anchor="e").grid(row=0, column=6, sticky="e", padx=5, pady=5)
        self.lost_packet_label = ttk.Label(counters_frame, text="0")
        self.lost_packet_label.grid(row=0, column=7, sticky="w", padx=5, pady=5)

        # Current Speed Display Frame
        speed_frame = ttk.LabelFrame(self.root, text="Current Speed")
        speed_frame.grid(row=6, column=0, columnspan=10, padx=10, pady=5, sticky="ew")
        for col in range(4):
            speed_frame.grid_columnconfigure(col, weight=1)

        # Speed Label
        ttk.Label(speed_frame, text="Speed:", anchor="e").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.current_speed_label = ttk.Label(speed_frame, text="0 KB/s | 0 Mbps")
        self.current_speed_label.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # Controls Frame
        controls_frame = ttk.Frame(self.root)
        controls_frame.grid(row=7, column=0, columnspan=10, padx=10, pady=10, sticky="ew")
        for col in range(3):
            controls_frame.grid_columnconfigure(col, weight=1)

        # Start Button
        self.start_button = ttk.Button(controls_frame, text="Start", command=self.start_sending)
        self.start_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # Stop Button
        self.stop_button = ttk.Button(controls_frame, text="Stop", command=self.stop_sending, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Clear Button
        self.clear_button = ttk.Button(controls_frame, text="Clear", command=self.clear_all)
        self.clear_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

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

        self.debug_text = ScrolledText(debug_frame, state="disabled", wrap="word")
        self.debug_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # Collect all interactive widgets for easy enabling/disabling
        self.interactive_widgets = [
            self.source_port_combo,
            self.destination_port_combo,
            self.packet_size_entry,
            self.packets_per_second_entry,
            self.max_packets_entry,
            self.handshake_chk,
            self.delay_chk,
            self.verbose_chk,
            self.protocol_version_chk,
            self.source_mac_chk,
            self.unique_id_chk,
            self.payload_signature_chk,
            self.autotune_chk,
            self.clear_button,
            self.target_port_entry  # Added Target Port entry to interactive widgets
        ]

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
        """
        Autotune loop that adjusts packet size and PPS based on packet loss and interface status.
        Runs only while sending is active.
        """
        # Retrieve autotune settings
        interval = self.user_settings.get("autotune_interval", 5)  # seconds
        max_packs = self.user_settings.get("max_packs_per_sec", 5000)
        min_packs = self.user_settings.get("min_packs_per_sec", 50)
        max_size = self.user_settings.get("max_packet_size", 32768)  # bytes
        min_size = self.user_settings.get("min_packet_size", 5000)   # bytes

        # Step sizes
        packs_decrement = self.user_settings.get("autotune_packs_decrement", 50)  # Decrease by 50 PPS
        size_decrement = self.user_settings.get("autotune_size_decrement", 500)   # Decrease by 500 bytes
        packs_increment = self.user_settings.get("autotune_packs_increment", 50)    # Increase by 50 PPS
        size_increment = self.user_settings.get("autotune_size_increment", 500)   # Increase by 500 bytes

        # Counter for successful packets (for increasing PPS/size)
        consecutive_sent_without_loss = 0
        required_success_packets = 1000

        while self.autotune_running:
            time.sleep(interval)

            # Only run autotune if we are actively sending
            if not self.running:
                continue

            with self.lock:
                total_sent = self.packet_count
                total_lost_interval = self.lost_packets_interval
            current_time = time.perf_counter()
            time_since_last_packet = current_time - self.last_packet_received_time

            # Define a threshold for considering no packets received as packet loss
            no_packet_threshold = interval * 2

            # Determine interface status
            interface_down = False
            if self.destination_port.get():
                iface_name = self.destination_port.get().split(" - ")[0]
                interface_status = self.get_interface_status(iface_name)
                if not interface_status:
                    interface_down = True
                    self.log(f"Autotune: Destination interface '{iface_name}' is DOWN.")

            # Check for packet loss based on interface status and received packets
            packet_loss_detected = False

            if interface_down:
                total_lost_interval = total_sent
                packet_loss_detected = True
                self.log(f"Autotune: Interface DOWN. Detected {total_sent} lost packet(s) this interval.")
            elif time_since_last_packet > no_packet_threshold:
                total_lost_interval = total_sent
                packet_loss_detected = True
                self.log(f"Autotune: No packets received in the last {no_packet_threshold} seconds. Detected {total_sent} lost packet(s) this interval.")

            if total_lost_interval > 0 or packet_loss_detected:
                with self.lock:
                    self.packet_count = 0
                    self.lost_packets_interval = 0
                    consecutive_sent_without_loss = 0

                current_pps = self.packets_per_second.get()
                current_size = self.packet_size.get()

                new_pps = max(min_packs, current_pps - packs_decrement)  # Decrease PPS
                new_size = max(min_size, current_size - size_decrement)  # Decrease size

                if new_pps != current_pps:
                    self.packets_per_second.set(new_pps)
                    self.log(f"Autotune: Decreasing PPS to {new_pps}.")
                else:
                    self.log("Autotune: PPS already at minimum limit.")

                if new_size != current_size:
                    self.packet_size.set(new_size)
                    self.log(f"Autotune: Decreasing Packet Size to {new_size} bytes.")
                else:
                    self.log("Autotune: Packet size already at minimum limit.")
            else:
                with self.lock:
                    consecutive_sent_without_loss += total_sent
                    self.packet_count = 0

                self.log(f"Autotune: {consecutive_sent_without_loss} consecutive packets sent without loss.")

                if consecutive_sent_without_loss >= required_success_packets:
                    consecutive_sent_without_loss = 0
                    current_pps = self.packets_per_second.get()
                    current_size = self.packet_size.get()

                    new_pps = min(max_packs, current_pps + packs_increment)  # Increase PPS
                    new_size = min(max_size, current_size + size_increment)  # Increase size

                    if new_pps != current_pps:
                        self.packets_per_second.set(new_pps)
                        self.log(f"Autotune: Increasing PPS to {new_pps}.")
                    else:
                        self.log("Autotune: PPS already at maximum limit.")

                    if new_size != current_size:
                        self.packet_size.set(new_size)
                        self.log(f"Autotune: Increasing Packet Size to {new_size} bytes.")
                    else:
                        self.log("Autotune: Packet size already at maximum limit.")

            self.root.after(0, lambda: self.lost_packet_label.config(text=str(self.lost_packets_total)))

    def get_interface_status(self, interface):
        """Return True if interface is up, else False."""
        try:
            stats = psutil.net_if_stats()
            if interface in stats and stats[interface].isup:
                return True
            return False
        except:
            return False

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
        try:
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
        except Exception as e:
            self.log(f"Error detecting network interfaces: {e}")
            self.source_port_combo["values"] = []
            self.destination_port_combo["values"] = []

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
        try:
            stats = psutil.net_if_stats()
            if interface in stats and stats[interface].isup:
                return "on"
            return "off"
        except:
            return "off"

    def update_leds(self, canvas, status):
        """Set canvas to green if 'on', else gray."""
        canvas.config(bg="green" if status else "gray")

    def monitor_link_status(self):
        """Periodic check of link status for source & destination LEDs."""
        try:
            if self.source_port.get():
                name = self.source_port.get().split(" - ")[0]
                st = self.get_interface_status(name)
                self.update_leds(self.source_link_led, st)
            if self.destination_port.get():
                name = self.destination_port.get().split(" - ")[0]
                st = self.get_interface_status(name)
                self.update_leds(self.destination_link_led, st)
        except Exception as e:
            self.log(f"Error monitoring link status: {e}")

        self.root.after(1000, self.monitor_link_status)

    def disable_widgets(self):
        """Disable all interactive widgets except the Stop button."""
        for widget in self.interactive_widgets:
            widget.config(state="disabled")

    def enable_widgets(self):
        """Enable all interactive widgets."""
        for widget in self.interactive_widgets:
            widget.config(state="normal")

    def start_sending(self):
        """'Start' button pressed: handshake/delay if needed, then send."""
        if self.running:
            self.log("Already running. Start command ignored.")
            return

        self.log("Start button pressed.")
        self.update_user_settings()

        # Disable all interactive widgets except Stop button
        self.disable_widgets()

        # Enable Stop button
        self.stop_button.config(state="normal")

        # Check link statuses
        sp = self.source_port.get()
        if sp:
            s_iface = sp.split(" - ")[0]
            if not self.get_interface_status(s_iface):
                self.log(f"WARNING: Source interface '{sp}' appears DOWN.")
            else:
                self.log(f"Source interface '{sp}' is UP.")

        dp = self.destination_port.get()
        if dp:
            d_iface = dp.split(" - ")[0]
            if not self.get_interface_status(d_iface):
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
            try:
                self.sock.close()
            except Exception as e:
                self.log(f"Error closing sender socket: {e}")
            self.sock = None
        self.status_text.set("Status: Stopped")

        # Re-enable all interactive widgets
        self.enable_widgets()

        # Disable Stop button
        self.stop_button.config(state="disabled")

    def stop_receiver(self):
        """Close the receiving socket to end the receiver thread."""
        if self.recv_sock:
            self.log("Stopping receiver socket...")
            try:
                self.recv_sock.close()
            except Exception as e:
                self.log(f"Error closing receiver socket: {e}")
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
            self.lost_packets_total = 0
            self.lost_packets_interval = 0
            self.last_packet_received_time = time.perf_counter()
            self.last_received_seq = -1  # Reset the last received sequence number

        self.bytes_sent_last_interval = 0  # Reset speed tracking

        self.sent_packet_label.config(text="0")
        self.received_packet_label.config(text="0")
        self.error_label.config(text="0")
        self.lost_packet_label.config(text="0")
        self.current_speed_label.config(text="0 KB/s | 0 Mbps")  # Reset speed display
        self.status_text.set("Status: Ready")

        self.debug_text.config(state="normal")
        self.debug_text.delete("1.0", tk.END)
        self.debug_text.config(state="disabled")

    def send_packets(self):
        """
        Create & bind the sending socket, then start a dedicated thread
        to send packets at the desired PPS.
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
            self.enable_widgets()
            self.stop_button.config(state="disabled")
            return

        target_port = self.target_port.get()
        pps = self.packets_per_second.get()
        if pps <= 0:
            pps = 1  # Prevent division by zero
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
            self.enable_widgets()
            self.stop_button.config(state="disabled")
            return

        # Start the sending thread
        self.sending_thread = threading.Thread(target=self.packet_sending_worker, args=(target_ip, target_port, pps, max_pkts), daemon=True)
        self.sending_thread.start()
        self.log("Packet sending thread started.")

    def packet_sending_worker(self, target_ip, target_port, pps, max_pkts):
        """Dedicated thread to send packets at precise intervals."""
        interval = 1.0 / pps  # Interval between packets in seconds
        next_send_time = time.perf_counter()

        while self.running:
            current_time = time.perf_counter()
            if current_time >= next_send_time:
                try:
                    packet = self.generate_packet(self.packet_count)
                    bytes_sent = self.sock.sendto(packet, (target_ip, target_port))

                    with self.lock:
                        self.packet_count += 1
                        self.bytes_sent_last_interval += bytes_sent
                        current_count = self.packet_count

                    self.root.after(0, lambda count=current_count: self.sent_packet_label.config(text=str(count)))

                    if self.var_verbose.get():
                        self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")
                    else:
                        if current_count % 100 == 0:
                            self.log(f"Sent packet #{current_count} ({bytes_sent} bytes).")

                    self.blink_activity_indicator()

                    if max_pkts > 0 and self.packet_count >= max_pkts:
                        self.log(f"Reached total send stop point ({max_pkts} packets). Stopping...")
                        self.root.after(0, self.stop_sending)
                        break

                except Exception as e:
                    with self.lock:
                        self.error_count += 1
                        current_error = self.error_count
                    self.root.after(0, lambda error=current_error: self.error_label.config(text=str(error)))
                    self.log(f"Send error: {e.__class__.__name__} - {e}")
                    self.root.after(0, lambda e=e: self.status_text.set(f"Send error: {e}"))
                    self.root.after(0, self.stop_sending)
                    break

                next_send_time += interval
            else:
                time_to_sleep = next_send_time - current_time
                if time_to_sleep > 0:
                    time.sleep(time_to_sleep)

    def generate_packet(self, seq_number):
        """
        Build the packet:
           [4-byte seq][Optional fields][Remaining 'X' bytes] + [4-byte CRC32]
        """
        user_size = self.packet_size.get()
        if user_size < 0:
            user_size = 0
        if user_size > 65507:
            self.log(f"WARNING: Packet size {user_size} exceeds 65507. Clamping.")
            user_size = 65507

        seq_header = struct.pack("I", seq_number)

        body = b""

        if self.var_protocol_version.get():
            protocol_version = b"Protocol-Version:1.0;"
            body += protocol_version

        if self.var_source_mac.get():
            source_mac = self.get_source_mac()
            body += f"Source-MAC:{source_mac};".encode("utf-8")

        if self.var_unique_id.get():
            unique_id = str(uuid.uuid4())
            body += f"UUID:{unique_id};".encode("utf-8")

        if self.var_payload_signature.get():
            checksum = zlib.crc32(body) & 0xFFFFFFFF
            payload_signature = f"Payload-CRC32:{checksum};".encode("utf-8")
            body += payload_signature

        overhead = 4 + len(body) + 4  # seq + body + CRC32
        remaining_size = max(0, user_size - overhead)
        body += b"X" * remaining_size

        full_payload = seq_header + body
        chksum = struct.pack("I", zlib.crc32(full_payload) & 0xFFFFFFFF)
        packet = full_payload + chksum
        return packet

    def get_source_mac(self):
        """Retrieve the MAC address of the selected source interface."""
        try:
            iface = self.source_port.get().split(" - ")[0]
            addrs = psutil.net_if_addrs()
            mac = None
            for addr in addrs[iface]:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    break
            if mac:
                mac_formatted = mac.upper().replace(":", "-")
                return mac_formatted
            else:
                return "00-00-00-00-00-00"
        except Exception as e:
            self.log(f"Error retrieving source MAC address: {e}")
            return "00-00-00-00-00-00"

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
                    self.lost_packets_total += gap
                    self.lost_packets_interval += gap
                self.log(f"Detected {gap} lost packet(s).")
                self.root.after(0, lambda: self.lost_packet_label.config(text=str(self.lost_packets_total)))
            self.last_received_seq = seq

        with self.lock:
            self.last_packet_received_time = time.perf_counter()

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
            self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

            actual_buffer_size = self.recv_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log(f"Receiver socket bound successfully with buffer size: {actual_buffer_size} bytes.")

            self.recv_sock.settimeout(2)
            self.recv_sock.bind((recv_ip, recv_port))

            self.log("Receiver socket bound. Listening for packets...")

            while self.running:
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

                if self.verify_packet(data):
                    with self.lock:
                        self.received_packet_count += 1
                        current_received = self.received_packet_count
                    self.root.after(0, lambda received=current_received: self.received_packet_label.config(text=str(received)))
                else:
                    with self.lock:
                        self.error_count += 1
                        current_error = self.error_count
                    self.root.after(0, lambda error=current_error: self.error_label.config(text=str(error)))

                self.blink_activity_indicator()

        except Exception as e:
            self.log(f"Receiver thread error: {e} - {traceback.format_exc()}")

    def blink_activity_indicator(self):
        """Blink the activity indicator without affecting the link LEDs."""
        original_text = self.status_text.get()
        self.status_text.set("Activity Detected")
        self.root.after(100, lambda: self.status_text.set(original_text))

    def blink_led(self, canvas, port_var):
        """Blink LED to yellow, then revert to green/gray based on actual link status."""
        iface_name = None
        if port_var.get():
            iface_name = port_var.get().split(" - ")[0]
        canvas.config(bg="yellow")
        self.root.after(100, lambda: self.update_leds(canvas, self.get_interface_status(iface_name)))

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
        with self.lock:
            bytes_sent = self.bytes_sent_last_interval
            bits_sent = bytes_sent * 8
            self.bytes_sent_last_interval = 0

        speed_kb = bytes_sent / 1024
        if speed_kb < 1024:
            speed_mbps = bits_sent / (1000 * 1000)
            speed_str = f"{speed_kb:.2f} KB/s | {speed_mbps:.2f} Mbps"
        else:
            speed_mb = speed_kb / 1024
            speed_mbps = bits_sent / (1000 * 1000)
            speed_str = f"{speed_mb:.2f} MB/s | {speed_mbps:.2f} Mbps"

        self.current_speed_label.config(text=speed_str)
        self.root.after(1000, self.update_speed)

# Entry point
if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("The 'psutil' library is required but not installed.")
        print("Please install it using 'pip install psutil' and try again.")
        sys.exit(1)

    root = tk.Tk()
    root.resizable(True, True)
    app = PacketGeneratorApp(root)
    root.mainloop()
