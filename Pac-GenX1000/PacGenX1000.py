#!/usr/bin/env python3
"""
Enterprise Packet Generator (Enterprise Professional Edition)
with UDP or TCP (mutually exclusive) option.

This application creates complete packets containing a 4-byte sequence,
optional header fields, an optional HMAC signature header, and a final
CRC32 checksum. It supports four configurable ports for TX/RX and “takes over”
the selected network interfaces. You may choose to send the packets over UDP
or TCP (but not both simultaneously). In addition, the program will force
each socket to use the physical network interface (if supported) using the
SO_BINDTODEVICE option on Linux and SO_DONTROUTE on Windows.

IMPORTANT: To see true physical packet loss when the cable is unplugged, ensure
that the physical interface is used. With this update, if the cable is unplugged
the sender will not loop back the packets internally but will instead update the
lost-packet counters and wait for the cable to be reconnected before resuming.

Author: Your Name
Date: 2025-02-08
"""

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
import zlib
import sys
import uuid
import hmac
import hashlib
import logging

# Shared secret key for HMAC signing
SECRET_KEY = b'secret-key'

# Maximum UDP payload size (in bytes)
MAX_UDP_PAYLOAD = 65507

# Configuration file and constants
CONFIG_FILE = "packet_gen_config.json"
PORT_NAMES = ['A', 'B', 'C', 'D']

# ------------------------------------------------------------------------------
# Custom logger that writes to the debug widget if verbose logging is enabled.
# ------------------------------------------------------------------------------
class WidgetLogger(logging.Handler):
    def __init__(self, text_widget, verbose_var):
        super().__init__()
        self.text_widget = text_widget
        self.verbose_var = verbose_var

    def emit(self, record):
        if not self.verbose_var.get():
            return
        msg = self.format(record)
        def append():
            self.text_widget.config(state="normal")
            self.text_widget.insert("end", msg + "\n")
            self.text_widget.see("end")
            self.text_widget.config(state="disabled")
        self.text_widget.after(0, append)

# ------------------------------------------------------------------------------
# Main Application Class
# ------------------------------------------------------------------------------
class PacketGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Generator (Enterprise Professional Edition)")
        self.root.geometry("1300x850")
        self.running = False

        # Default configuration settings.
        self.default_settings = {
            "target_port": 12345,
            "packet_size": 32768,  # This field now holds the filler length.
            "packets_per_second": 1000,
            "max_packets": 1000,
            "use_handshake": False,
            "use_start_delay": False,
            "use_verbose": False,
            "add_protocol_version": False,
            "add_source_mac": False,
            "add_unique_id": False,
            "add_payload_signature": False,
            "max_packet_size": MAX_UDP_PAYLOAD,
            "min_packet_size": 40,
            "max_packs_per_sec": 5000,
            "min_packs_per_sec": 1
        }
        self.user_settings = self.load_config()

        # Configuration variables.
        self.target_port = tk.IntVar(value=self.user_settings.get("target_port", 12345))
        self.packet_size = tk.IntVar(value=self.user_settings.get("packet_size", 32768))
        self.packets_per_second = tk.IntVar(value=self.user_settings.get("packets_per_second", 1000))
        self.max_packets = tk.IntVar(value=self.user_settings.get("max_packets", 1000))

        self.var_handshake = tk.BooleanVar(value=self.user_settings.get("use_handshake", False))
        self.var_start_delay = tk.BooleanVar(value=self.user_settings.get("use_start_delay", False))
        self.var_verbose = tk.BooleanVar(value=self.user_settings.get("use_verbose", False))
        self.var_protocol_version = tk.BooleanVar(value=self.user_settings.get("add_protocol_version", False))
        self.var_source_mac = tk.BooleanVar(value=self.user_settings.get("add_source_mac", False))
        self.var_unique_id = tk.BooleanVar(value=self.user_settings.get("add_unique_id", False))
        self.var_payload_signature = tk.BooleanVar(value=self.user_settings.get("add_payload_signature", False))
        self.var_random = tk.BooleanVar(value=False)
        self.var_latency = tk.BooleanVar(value=False)
        self.var_hmac = tk.BooleanVar(value=False)
        self.var_ext_a = tk.BooleanVar(value=False)
        self.var_ext_b = tk.BooleanVar(value=False)
        # Use a single radio-button variable for protocol selection.
        # VALID VALUES: "UDP" or "TCP" (default now set to "TCP").
        self.protocol_choice = tk.StringVar(value="TCP")

        self.random_payload = None

        # Port counters and sequence trackers.
        self.port_counters = {port: {"TX": 0, "RX": 0, "Errors": 0, "Lost": 0,
                                     "Bytes_TX": 0, "Bytes_RX": 0} for port in PORT_NAMES}
        self.port_seq = {port: 0 for port in PORT_NAMES}
        self.port_last_seq = {port: -1 for port in PORT_NAMES}

        # Containers for UDP sockets and threads.
        self.sending_socks = {}
        self.sending_threads = {}
        self.recv_socks = {}
        self.receiver_threads = {}

        # Containers for TCP sockets and threads.
        self.tcp_sending_socks = {}      # For each TX port: dict mapping destination port letter to TCP socket.
        self.tcp_sending_threads = {}    # For each TX port: one thread that sends via TCP.
        self.tcp_recv_socks = {}         # For each RX port: the TCP server socket.
        self.tcp_receiver_threads = {}   # For each RX port: thread(s) to accept connections.

        self.lock = threading.Lock()

        self.after_speed_id = None
        self.after_counters_id = None

        self.max_speed_record = 0.0
        self.start_time = time.perf_counter()
        # For instantaneous speed calculations:
        self.last_total_bytes = 0
        self.last_time = self.start_time

        self.port_comboboxes = {}
        self.port_tx_vars = {}
        self.port_rx_vars = {}
        self.counter_labels = {port: {} for port in PORT_NAMES}
        self.link_leds = {}

        self.setup_receiver_ports()
        self.tx_finished = {}  # Tracks which TX ports have finished sending.

        # Cached constant packet body (for UDP/TCP when random payload is disabled)
        self.cached_body = None
        self.cached_final_size = None

        self.create_widgets()
        self.maximize_window()
        self.setup_logging()

        self.detect_network_interfaces()
        self.apply_loaded_settings()

        self.log("Welcome to Packet Generator (Enterprise Professional Edition)!")
        if os.path.isfile(CONFIG_FILE):
            self.log("Settings loaded from configuration.")
        else:
            self.log("No config found; using defaults.")

        self.update_speed()
        self.update_counters_table()
        self.update_link_status()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------------------------- Helper: Bind Socket to Physical Interface --------------------------
    def bind_to_interface(self, sock, port):
        """If on Linux and SO_BINDTODEVICE is available, force the socket to use the selected NIC.
           On Windows, we use SO_DONTROUTE (set in the sender creation) to force physical transmission."""
        iface_str = self.port_comboboxes[port].get()
        if iface_str and " - " in iface_str:
            iface_name = iface_str.split(" - ")[0].strip()
            if sys.platform.startswith("linux") and hasattr(socket, "SO_BINDTODEVICE"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface_name.encode())
                    self.log(f"Bound socket for port {port} to device {iface_name}.")
                except Exception as e:
                    self.log(f"Error binding socket for port {port} to device {iface_name}: {e}")

    # -------------------------- TX Finish Helpers --------------------------
    def mark_tx_finished(self, port):
        """Called when a TX thread finishes sending max packets for a port."""
        with self.lock:
            self.tx_finished[port] = True
            all_finished = all(self.tx_finished.get(p, True) for p in PORT_NAMES if self.port_tx_vars[p].get())
        if all_finished:
            self.log("All TX ports have reached their max packet count.")
            self.root.after(0, self.reset_ui_after_stop)

    def reset_ui_after_stop(self):
        """Stop all activity and reset internal state (leaving displayed counters intact)
        so the user can start a new run without restarting the program."""
        self.stop_all_activity()
        self.reset_internal_state()
        self.enable_widgets()
        self.start_button.grid()
        self.clear_button.grid()
        self.log("System reset and ready for another run.")

    def reset_internal_state(self):
        """Reset internal state variables (sequence numbers, start time, TX tracking)
        without clearing displayed counter values."""
        for port in PORT_NAMES:
            self.port_seq[port] = 0
            self.port_last_seq[port] = -1
        self.start_time = time.perf_counter()
        self.last_total_bytes = 0
        self.last_time = self.start_time
        self.max_speed_record = 0.0
        self.tx_finished = {}

    # -------------------------- Configuration Methods --------------------------
    def load_config(self):
        if os.path.isfile(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                for key, value in self.default_settings.items():
                    data.setdefault(key, value)
                return data
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                return dict(self.default_settings)
        else:
            return dict(self.default_settings)

    def save_config(self):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.user_settings, f, indent=2)
            self.log("Configuration saved successfully.")
        except Exception as e:
            self.log(f"Error saving config: {e}")

    def update_user_settings(self):
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
        for port in PORT_NAMES:
            self.user_settings[f"nic_{port}"] = self.port_comboboxes[port].get()

    def apply_loaded_settings(self):
        self.target_port.set(self.user_settings.get("target_port", 12345))
        self.packet_size.set(self.user_settings.get("packet_size", 32768))
        self.packets_per_second.set(self.user_settings.get("packets_per_second", 1000))
        self.max_packets.set(self.user_settings.get("max_packets", 1000))
        self.var_handshake.set(self.user_settings.get("use_handshake", False))
        self.var_start_delay.set(self.user_settings.get("use_start_delay", False))
        self.var_verbose.set(self.user_settings.get("use_verbose", False))
        self.var_protocol_version.set(self.user_settings.get("add_protocol_version", False))
        self.var_source_mac.set(self.user_settings.get("add_source_mac", False))
        self.var_unique_id.set(self.user_settings.get("add_unique_id", False))
        self.var_payload_signature.set(self.user_settings.get("add_payload_signature", False))
        self.setup_receiver_ports()
        for port in PORT_NAMES:
            nic_key = f"nic_{port}"
            if nic_key in self.user_settings:
                self.port_comboboxes[port].set(self.user_settings[nic_key])

    def setup_receiver_ports(self):
        base = self.target_port.get()
        self.receiver_ports = {}
        for i, port in enumerate(PORT_NAMES):
            self.receiver_ports[port] = base + i

    # -------------------------- Logging Setup --------------------------
    def setup_logging(self):
        self.logger = logging.getLogger("PacketGen")
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S")

        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # File handler: Log to "packet_generator_debug.log" in the current directory.
        fh = logging.FileHandler("packet_generator_debug.log", mode='a')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        # Optional widget handler if the debug text widget exists.
        if hasattr(self, "debug_text"):
            wh = WidgetLogger(self.debug_text, self.var_verbose)
            wh.setFormatter(formatter)
            self.logger.addHandler(wh)

    def log(self, message):
        self.logger.debug(message)

    # -------------------------- GUI Creation --------------------------
    def create_widgets(self):
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
        self.bottom_frame = ttk.Frame(self.root)
        self.bottom_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        style = ttk.Style(self.root)
        try:
            style.configure("TCheckbutton", font=("Roboto", 12))
            style.configure("TLabel", font=("Roboto", 12))
            style.configure("TButton", font=("Roboto", 12))
            style.configure("TEntry", font=("Roboto", 12))
            style.configure("TCombobox", font=("Roboto", 12))
            style.configure("TLabelframe.Label", font=("Roboto", 14, "bold"))
        except Exception:
            style.configure("TCheckbutton", font=("Arial", 12))
            style.configure("TLabel", font=("Arial", 12))
            style.configure("TButton", font=("Arial", 12))
            style.configure("TEntry", font=("Arial", 12))
            style.configure("TCombobox", font=("Arial", 12))
            style.configure("TLabelframe.Label", font=("Arial", 14, "bold"))
        self.controls_frame = ttk.Frame(self.top_frame)
        self.controls_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.create_controls(self.controls_frame)
        self.status_frame = ttk.Frame(self.top_frame)
        self.status_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.create_status(self.status_frame)
        debug_frame = ttk.LabelFrame(self.bottom_frame, text="Debug Log")
        debug_frame.pack(fill="both", expand=True)
        self.debug_text = ScrolledText(debug_frame, state="disabled", wrap="word")
        self.debug_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.interactive_widgets = []
        for widget in [self.packet_size_entry, self.packets_per_second_entry, self.max_packets_entry,
                       self.handshake_chk, self.delay_chk, self.verbose_chk,
                       self.protocol_version_chk, self.source_mac_chk, self.unique_id_chk, self.payload_signature_chk]:
            self.interactive_widgets.append(widget)
        self.interactive_widgets.extend(list(self.port_comboboxes.values()))
        # Use radio buttons for protocol selection.
        protocol_frame = ttk.Frame(self.controls_frame)
        protocol_frame.pack(anchor="w", pady=2)
        ttk.Label(protocol_frame, text="Select Protocol:").pack(side="left")
        udp_rb = ttk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_choice, value="UDP")
        udp_rb.pack(side="left", padx=5)
        tcp_rb = ttk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_choice, value="TCP")
        tcp_rb.pack(side="left", padx=5)
        self.interactive_widgets.extend([udp_rb, tcp_rb])
        for var in (self.var_protocol_version, self.var_source_mac, self.var_unique_id,
                    self.var_payload_signature, self.var_hmac, self.var_ext_a, self.var_ext_b):
            var.trace_add("write", lambda *args: self.update_header_length_label())

    def create_controls(self, parent):
        port_config_frame = ttk.LabelFrame(parent, text="Port Configuration")
        port_config_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(port_config_frame, text="Port").grid(row=0, column=0, padx=5, pady=3)
        ttk.Label(port_config_frame, text="Interface").grid(row=0, column=1, padx=5, pady=3)
        ttk.Label(port_config_frame, text="TX").grid(row=0, column=2, padx=5, pady=3)
        ttk.Label(port_config_frame, text="RX").grid(row=0, column=3, padx=5, pady=3)
        ttk.Label(port_config_frame, text="Link").grid(row=0, column=4, padx=5, pady=3)
        for i, port in enumerate(PORT_NAMES):
            ttk.Label(port_config_frame, text=port).grid(row=i+1, column=0, padx=5, pady=3)
            var = tk.StringVar()
            cb = ttk.Combobox(port_config_frame, textvariable=var, state="readonly", width=30)
            cb.grid(row=i+1, column=1, padx=5, pady=3)
            self.port_comboboxes[port] = cb
            tx_var = tk.BooleanVar(value=True)
            rx_var = tk.BooleanVar(value=True)
            self.port_tx_vars[port] = tx_var
            self.port_rx_vars[port] = rx_var
            ttk.Checkbutton(port_config_frame, variable=tx_var).grid(row=i+1, column=2, padx=5, pady=3)
            ttk.Checkbutton(port_config_frame, variable=rx_var).grid(row=i+1, column=3, padx=5, pady=3)
            led_canvas = tk.Canvas(port_config_frame, width=20, height=20, highlightthickness=0)
            led_canvas.grid(row=i+1, column=4, padx=5, pady=3)
            led_canvas.create_oval(2, 2, 18, 18, fill="red", outline="black")
            self.link_leds[port] = led_canvas
        refresh_btn = ttk.Button(port_config_frame, text="Refresh Interfaces", command=self.detect_network_interfaces)
        refresh_btn.grid(row=len(PORT_NAMES)+1, column=0, columnspan=5, pady=5)
        packet_frame = ttk.LabelFrame(parent, text="Packet Settings")
        packet_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(packet_frame, text="Filler Size (Bytes):", anchor="w").grid(row=0, column=0, padx=5, pady=3)
        self.packet_size_entry = ttk.Entry(packet_frame, textvariable=self.packet_size)
        self.packet_size_entry.grid(row=0, column=1, padx=5, pady=3, sticky="ew")
        ttk.Label(packet_frame, text="Packets per Second:", anchor="w").grid(row=0, column=2, padx=5, pady=3)
        self.packets_per_second_entry = ttk.Entry(packet_frame, textvariable=self.packets_per_second)
        self.packets_per_second_entry.grid(row=0, column=3, padx=5, pady=3, sticky="ew")
        ttk.Label(packet_frame, text="Max Packets (>0):", anchor="w").grid(row=1, column=0, padx=5, pady=3)
        self.max_packets_entry = ttk.Entry(packet_frame, textvariable=self.max_packets)
        self.max_packets_entry.grid(row=1, column=1, padx=5, pady=3, sticky="ew")
        features_frame = ttk.LabelFrame(parent, text="Features")
        features_frame.pack(fill="x", padx=5, pady=5)
        self.handshake_chk = ttk.Checkbutton(features_frame, text="Enable Handshake", variable=self.var_handshake)
        self.handshake_chk.grid(row=0, column=0, padx=5, pady=3, sticky="w")
        self.delay_chk = ttk.Checkbutton(features_frame, text="Start Delay (3s)", variable=self.var_start_delay)
        self.delay_chk.grid(row=0, column=1, padx=5, pady=3, sticky="w")
        self.verbose_chk = ttk.Checkbutton(features_frame, text="Verbose Logging", variable=self.var_verbose)
        self.verbose_chk.grid(row=0, column=2, padx=5, pady=3, sticky="w")
        self.protocol_version_chk = ttk.Checkbutton(features_frame, text="Add Protocol Version", variable=self.var_protocol_version)
        self.protocol_version_chk.grid(row=1, column=0, padx=5, pady=3, sticky="w")
        self.source_mac_chk = ttk.Checkbutton(features_frame, text="Add Source MAC Address", variable=self.var_source_mac)
        self.source_mac_chk.grid(row=1, column=1, padx=5, pady=3, sticky="w")
        self.unique_id_chk = ttk.Checkbutton(features_frame, text="Add Unique Identifier", variable=self.var_unique_id)
        self.unique_id_chk.grid(row=1, column=2, padx=5, pady=3, sticky="w")
        self.payload_signature_chk = ttk.Checkbutton(features_frame, text="Add Payload Signature", variable=self.var_payload_signature)
        self.payload_signature_chk.grid(row=1, column=3, padx=5, pady=3, sticky="w")
        self.random_chk = ttk.Checkbutton(features_frame, text="Enable Random Payload", variable=self.var_random)
        self.random_chk.grid(row=2, column=0, padx=5, pady=3, sticky="w")
        self.latency_chk = ttk.Checkbutton(features_frame, text="Enable Latency Measurement", variable=self.var_latency)
        self.latency_chk.grid(row=2, column=1, padx=5, pady=3, sticky="w")
        self.hmac_chk = ttk.Checkbutton(features_frame, text="Enable HMAC Signing", variable=self.var_hmac)
        self.hmac_chk.grid(row=2, column=2, padx=5, pady=3, sticky="w")
        self.ext_a_chk = ttk.Checkbutton(features_frame, text="Enable Extended Option A (+50 bytes)", variable=self.var_ext_a)
        self.ext_a_chk.grid(row=3, column=0, padx=5, pady=3, sticky="w")
        self.ext_b_chk = ttk.Checkbutton(features_frame, text="Enable Extended Option B (+100 bytes)", variable=self.var_ext_b)
        self.ext_b_chk.grid(row=3, column=1, padx=5, pady=3, sticky="w")
        self.header_length_label = ttk.Label(features_frame, text="Protocol Header Overhead: 0 bytes | Max Filler: 0 bytes")
        self.header_length_label.grid(row=4, column=0, columnspan=4, padx=5, pady=3, sticky="w")
        self.update_header_length_label()

    def create_status(self, parent):
        counters_frame = ttk.LabelFrame(parent, text="Port Counters")
        counters_frame.pack(fill="x", padx=5, pady=5)
        headers = ["Port", "TX", "RX", "Errors", "Lost"]
        for j, h in enumerate(headers):
            ttk.Label(counters_frame, text=h, font=("Roboto", 12, "bold")).grid(row=0, column=j, padx=5, pady=3)
        for i, port in enumerate(PORT_NAMES):
            ttk.Label(counters_frame, text=port).grid(row=i+1, column=0, padx=5, pady=3)
            self.counter_labels[port] = {}
            self.counter_labels[port]['TX'] = ttk.Label(counters_frame, text="0")
            self.counter_labels[port]['TX'].grid(row=i+1, column=1, padx=5, pady=3)
            self.counter_labels[port]['RX'] = ttk.Label(counters_frame, text="0")
            self.counter_labels[port]['RX'].grid(row=i+1, column=2, padx=5, pady=3)
            self.counter_labels[port]['Errors'] = ttk.Label(counters_frame, text="0")
            self.counter_labels[port]['Errors'].grid(row=i+1, column=3, padx=5, pady=3)
            self.counter_labels[port]['Lost'] = ttk.Label(counters_frame, text="0")
            self.counter_labels[port]['Lost'].grid(row=i+1, column=4, padx=5, pady=3)
        speed_frame = ttk.LabelFrame(parent, text="Current Speed (Received)")
        speed_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(speed_frame, text="Total Received:", anchor="w").grid(row=0, column=0, padx=5, pady=3)
        self.total_received_label = ttk.Label(speed_frame, text="0 B")
        self.total_received_label.grid(row=0, column=1, padx=5, pady=3, sticky="w")
        ttk.Label(speed_frame, text="Max Speed:", anchor="w").grid(row=1, column=0, padx=5, pady=3)
        self.max_speed_label = ttk.Label(speed_frame, text="0 Mbps")
        self.max_speed_label.grid(row=1, column=1, padx=5, pady=3, sticky="w")
        ttk.Label(speed_frame, text="Average Speed:", anchor="w").grid(row=2, column=0, padx=5, pady=3)
        self.average_speed_label = ttk.Label(speed_frame, text="0 Mbps")
        self.average_speed_label.grid(row=2, column=1, padx=5, pady=3, sticky="w")
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill="x", padx=5, pady=10)
        self.start_button = ttk.Button(controls_frame, text="Start", command=self.start_all)
        self.start_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.stop_button = ttk.Button(controls_frame, text="Stop", command=self.stop_all_activity, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.clear_button = ttk.Button(controls_frame, text="Clear", command=self.clear_all)
        self.clear_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")
        controls_frame.grid_columnconfigure(0, weight=1)
        controls_frame.grid_columnconfigure(1, weight=1)
        controls_frame.grid_columnconfigure(2, weight=1)

    def update_header_length_label(self):
        overhead = 4
        temp = b""
        if self.var_protocol_version.get():
            temp += b"Protocol-Version:1.0;"
        if self.var_source_mac.get():
            temp += f"Source-MAC:{'AA-BB-CC-DD-EE-FF'};".encode("utf-8")
        if self.var_unique_id.get():
            temp += f"UUID:{'0'*36};".encode("utf-8")
        if self.var_payload_signature.get():
            temp += f"Payload-CRC32:{0};".encode("utf-8")
        overhead += len(temp)
        if self.var_hmac.get():
            overhead += 70
        if self.var_ext_a.get():
            overhead += 50
        if self.var_ext_b.get():
            overhead += 100
        max_filler = MAX_UDP_PAYLOAD - (overhead + 4)
        self.header_length_label.config(text=f"Protocol Header Overhead: {overhead} bytes | Max Filler: {max_filler} bytes")
        self.packet_size.set(max_filler)

    def maximize_window(self):
        try:
            if sys.platform.startswith('win'):
                self.root.state('zoomed')
            elif sys.platform.startswith('darwin'):
                self.root.attributes('-zoomed', True)
            else:
                self.root.state('zoomed')
        except Exception:
            pass

    # -------------------------- Network & Packet Methods --------------------------
    def detect_network_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            available_interfaces = []
            for iface_name, iface_info in interfaces.items():
                lower_name = iface_name.lower()
                if any(x in lower_name for x in ["lo", "loopback", "wi-fi", "wireless", "wlan", "bluetooth"]):
                    continue
                for addr in iface_info:
                    if addr.family == socket.AF_INET:
                        if addr.address.startswith("127.") or addr.address.startswith("169.254."):
                            continue
                        available_interfaces.append(f"{iface_name} - {addr.address}")
            for port in PORT_NAMES:
                self.port_comboboxes[port]["values"] = available_interfaces
                if available_interfaces:
                    self.port_comboboxes[port].set(available_interfaces[0])
            self.log("Detected interfaces: " + str(available_interfaces))
        except Exception as e:
            self.log(f"Error detecting network interfaces: {e}")
            for port in PORT_NAMES:
                self.port_comboboxes[port]["values"] = []

    def update_link_status(self):
        stats = psutil.net_if_stats()
        for port in PORT_NAMES:
            iface_str = self.port_comboboxes[port].get()
            iface_name = iface_str.split(" - ")[0] if iface_str and " - " in iface_str else None
            if iface_name and iface_name in stats and stats[iface_name].isup and stats[iface_name].speed > 0:
                # Check if either TX or RX thread (UDP or TCP) is active.
                tx_active = self.port_tx_vars[port].get() and (
                    (port in self.sending_threads and self.sending_threads[port].is_alive()) or
                    (port in self.tcp_sending_threads and self.tcp_sending_threads[port].is_alive())
                )
                rx_active = self.port_rx_vars[port].get() and (
                    (port in self.receiver_threads and self.receiver_threads[port].is_alive()) or
                    (port in self.tcp_receiver_threads and self.tcp_receiver_threads[port].is_alive())
                )
                if tx_active or rx_active:
                    color = "yellow"
                else:
                    color = "green"
            else:
                color = "red"
            canvas = self.link_leds[port]
            canvas.delete("all")
            canvas.create_oval(2, 2, 18, 18, fill=color, outline="black")
        # Update more frequently for responsiveness.
        self.root.after(500, self.update_link_status)

    def validate_fields(self):
        try:
            size = int(self.packet_size.get())
        except Exception:
            size = self.default_settings["packet_size"]
        min_allowed = 0
        max_allowed = MAX_UDP_PAYLOAD
        if size < min_allowed:
            size = min_allowed
        if size > max_allowed:
            size = max_allowed
        self.packet_size.set(size)
        try:
            pps = int(self.packets_per_second.get())
        except Exception:
            pps = self.default_settings["packets_per_second"]
        if pps < self.default_settings["min_packs_per_sec"]:
            pps = self.default_settings["min_packs_per_sec"]
        if pps > self.default_settings["max_packs_per_sec"]:
            pps = self.default_settings["max_packs_per_sec"]
        self.packets_per_second.set(pps)
        try:
            max_pkts = int(self.max_packets.get())
        except Exception:
            max_pkts = self.default_settings["max_packets"]
        if max_pkts <= 0:
            max_pkts = self.default_settings["max_packets"]
        self.max_packets.set(max_pkts)

    def prepare_cached_body(self):
        if self.var_random.get():
            self.cached_body = None
            return
        filler_length = self.packet_size.get()
        header_fields = b""
        if self.var_protocol_version.get():
            header_fields += b"Protocol-Version:1.0;"
        if self.var_source_mac.get():
            mac = self.get_source_mac()
            header_fields += f"Source-MAC:{mac};".encode("utf-8")
        if self.var_unique_id.get():
            header_fields += f"UUID:{str(uuid.uuid4())};".encode("utf-8")
        if self.var_payload_signature.get():
            header_fields += f"Payload-CRC32:{0};".encode("utf-8")
        filler = b"X" * filler_length
        temp_body = header_fields + filler
        if self.var_hmac.get():
            computed_hmac = hmac.new(SECRET_KEY, temp_body, hashlib.sha256).hexdigest()
            hmac_header = f"HMAC:{computed_hmac};".encode("utf-8")
            self.cached_body = hmac_header + temp_body
        else:
            self.cached_body = temp_body

    def generate_packet(self, seq_number):
        seq_header = struct.pack("I", seq_number)
        header_fields = b""
        if self.var_protocol_version.get():
            header_fields += b"Protocol-Version:1.0;"
        if self.var_source_mac.get():
            mac = self.get_source_mac()
            header_fields += f"Source-MAC:{mac};".encode("utf-8")
        if self.var_unique_id.get():
            header_fields += f"UUID:{str(uuid.uuid4())};".encode("utf-8")
        if self.var_payload_signature.get():
            header_fields += f"Payload-CRC32:{0};".encode("utf-8")
        filler_length = self.packet_size.get()
        if self.var_random.get():
            filler = os.urandom(filler_length)
        else:
            filler = b"X" * filler_length
        temp_body = header_fields + filler
        if self.var_hmac.get():
            computed_hmac = hmac.new(SECRET_KEY, temp_body, hashlib.sha256).hexdigest()
            hmac_header = f"HMAC:{computed_hmac};".encode("utf-8")
            body = hmac_header + temp_body
        else:
            body = temp_body
        full_payload = seq_header + body
        chksum = struct.pack("I", zlib.crc32(full_payload) & 0xFFFFFFFF)
        packet = full_payload + chksum
        return packet

    def get_source_mac(self):
        for port in PORT_NAMES:
            if self.port_tx_vars[port].get():
                try:
                    iface = self.port_comboboxes[port].get().split(" - ")[0]
                    addrs = psutil.net_if_addrs()
                    for addr in addrs.get(iface, []):
                        if hasattr(socket, "AF_LINK") and addr.family == socket.AF_LINK:
                            mac = addr.address
                            if mac:
                                return mac.upper().replace(":", "-")
                        elif addr.family == psutil.AF_LINK or addr.family == getattr(socket, "AF_PACKET", None):
                            mac = addr.address
                            if mac:
                                return mac.upper().replace(":", "-")
                    break
                except Exception as e:
                    self.log(f"Error retrieving MAC for port {port}: {e}")
                    break
        return "00-00-00-00-00-00"

    # -------------------------- TX/RX Methods --------------------------
    def start_all(self):
        if self.running:
            self.log("Already running; ignoring start command.")
            return
        max_pkts = int(self.max_packets.get())
        if any(self.port_tx_vars[port].get() and self.port_seq[port] >= max_pkts for port in PORT_NAMES):
            self.clear_all()
        self.validate_fields()
        self.update_user_settings()
        self.start_button.grid_remove()
        self.clear_button.grid_remove()
        self.stop_button.config(state="normal")
        for widget in self.interactive_widgets:
            widget.config(state="disabled")
        self.running = True
        self.tx_finished = {port: False for port in PORT_NAMES if self.port_tx_vars[port].get()}
        self.log("Starting TX/RX on selected ports.")
        if self.var_start_delay.get():
            self.log("Delaying start by 3 seconds...")
            self.root.after(3000, self.do_pre_send_actions)
        else:
            self.do_pre_send_actions()

    def do_pre_send_actions(self):
        if not self.running:
            return
        if self.var_handshake.get():
            self.send_handshake_with_latency()
        self.prepare_cached_body()
        protocol = self.protocol_choice.get()
        if protocol == "UDP":
            self.start_udp_sending_threads()
            self.start_udp_receiver_threads()
        elif protocol == "TCP":
            self.start_tcp_sending_threads()
            self.start_tcp_receiver_threads()

    def send_handshake_with_latency(self):
        for port in PORT_NAMES:
            if self.port_tx_vars[port].get():
                iface_info = self.port_comboboxes[port].get().split(" - ")
                sender_ip = iface_info[1].strip() if len(iface_info) > 1 else "0.0.0.0"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((sender_ip, 0))
                    self.bind_to_interface(sock, port)
                    if self.var_latency.get():
                        timestamp = str(time.perf_counter())
                        message = f"HELLO:{timestamp}".encode("utf-8")
                    else:
                        message = b"HELLO"
                    for dport in PORT_NAMES:
                        if self.port_rx_vars[dport].get():
                            dest_iface = self.port_comboboxes[dport].get().split(" - ")
                            dest_ip = dest_iface[1].strip() if len(dest_iface) > 1 else sender_ip
                            dest_port = self.receiver_ports[dport]
                            stats = psutil.net_if_stats()
                            dest_iface_name = dest_iface[0] if len(dest_iface) > 0 else None
                            if dest_iface_name and dest_iface_name in stats and stats[dest_iface_name].isup and stats[dest_iface_name].speed > 0:
                                sock.sendto(message, (dest_ip, dest_port))
                                self.log(f"Handshake from port {port} ({sender_ip}) to port {dport} ({dest_ip}:{dest_port}).")
                            else:
                                self.log(f"Skipping handshake to port {dport} because interface {dest_iface_name} is down.")
                    sock.close()
                except Exception as e:
                    self.log(f"Error sending handshake from port {port}: {e}")

    # ----- UDP Methods -----
    def start_udp_sending_threads(self):
        pps = self.packets_per_second.get()
        if pps < 1:
            self.log(f"Packets per second too low ({pps}). Using 1 PPS.")
            pps = 1
            self.packets_per_second.set(1)
        max_pkts = self.max_packets.get()
        for port in PORT_NAMES:
            if self.port_tx_vars[port].get():
                iface = self.port_comboboxes[port].get()
                iface_parts = iface.split(" - ")
                iface_ip = iface_parts[1].strip() if len(iface_parts) > 1 else "0.0.0.0"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((iface_ip, 0))
                    self.bind_to_interface(sock, port)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                    # Force physical transmission by disabling routing.
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_DONTROUTE, 1)
                    self.sending_socks[port] = sock
                    self.log(f"UDP Port {port} TX socket bound on {iface_ip}.")
                except Exception as e:
                    self.log(f"Error binding UDP TX socket on port {port}: {e}")
                    continue
                thread = threading.Thread(target=self.packet_sending_worker_udp, args=(port, pps, max_pkts))
                thread.daemon = True
                self.sending_threads[port] = thread
                thread.start()
                self.log(f"Started UDP TX thread for port {port}.")

    def packet_sending_worker_udp(self, port, pps, max_pkts):
        interval = 1.0 / pps
        next_send_time = time.perf_counter()
        while self.running:
            # Check physical interface state
            stats = psutil.net_if_stats()
            iface_str = self.port_comboboxes[port].get()
            iface_name = iface_str.split(" - ")[0] if iface_str and " - " in iface_str else None
            if not iface_name or iface_name not in stats or not stats[iface_name].isup or stats[iface_name].speed == 0:
                self.log(f"UDP Port {port} TX: Interface {iface_name} is down. Waiting for reconnection.")
                time.sleep(1)
                with self.lock:
                    self.port_counters[port]["Lost"] += 1
                next_send_time += interval
                self.port_seq[port] += 1
                continue

            now = time.perf_counter()
            if now >= next_send_time:
                try:
                    seq = self.port_seq[port]
                    packet = self.generate_packet(seq)
                    total_bytes_sent = 0
                    current_stats = psutil.net_if_stats()
                    for dport in PORT_NAMES:
                        if self.port_rx_vars[dport].get():
                            iface = self.port_comboboxes[dport].get()
                            dest_parts = iface.split(" - ")
                            dest_ip = dest_parts[1].strip() if len(dest_parts) > 1 else "0.0.0.0"
                            dest_port = self.receiver_ports[dport]
                            dest_iface_name = dest_parts[0] if len(dest_parts) > 0 else None
                            if dest_iface_name and dest_iface_name in current_stats and current_stats[dest_iface_name].isup and current_stats[dest_iface_name].speed > 0:
                                try:
                                    bytes_sent = self.sending_socks[port].sendto(packet, (dest_ip, dest_port))
                                    total_bytes_sent += bytes_sent
                                except Exception as e:
                                    with self.lock:
                                        self.port_counters[port]["Errors"] += 1
                                        self.port_counters[port]["Lost"] += 1
                                    self.log(f"UDP Port {port} TX error sending to port {dport} ({dest_ip}:{dest_port}): {e}")
                            else:
                                self.log(f"Skipping sending to UDP port {dport} because interface {dest_iface_name} is down.")
                    with self.lock:
                        self.port_counters[port]["TX"] += 1
                        self.port_counters[port]["Bytes_TX"] += total_bytes_sent
                except Exception as e:
                    with self.lock:
                        self.port_counters[port]["Errors"] += 1
                        self.port_counters[port]["Lost"] += 1
                    self.log(f"UDP Port {port} TX error: {e}")
                next_send_time += interval
                self.port_seq[port] += 1
                if max_pkts > 0 and self.port_seq[port] >= max_pkts:
                    self.log(f"UDP Port {port} reached max packet count ({max_pkts}).")
                    self.mark_tx_finished(port)
                    break
            else:
                remaining = next_send_time - now
                while remaining > 0 and self.running:
                    time.sleep(min(0.1, remaining))
                    remaining = next_send_time - time.perf_counter()

    def start_udp_receiver_threads(self):
        for port in PORT_NAMES:
            if self.port_rx_vars[port].get():
                iface = self.port_comboboxes[port].get()
                iface_parts = iface.split(" - ")
                iface_ip = iface_parts[1].strip() if len(iface_parts) > 1 else "0.0.0.0"
                recv_port = self.receiver_ports[port]
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                    sock.settimeout(2)
                    sock.bind((iface_ip, recv_port))
                    self.bind_to_interface(sock, port)
                    self.recv_socks[port] = sock
                    self.log(f"UDP Port {port} RX socket bound on {iface_ip}:{recv_port}.")
                except Exception as e:
                    self.log(f"Error binding UDP RX socket on port {port}: {e}")
                    continue
                thread = threading.Thread(target=self.receive_packets_udp, args=(port, recv_port))
                thread.daemon = True
                self.receiver_threads[port] = thread
                thread.start()
                self.log(f"Started UDP RX thread for port {port}.")

    def receive_packets_udp(self, port, recv_port):
        sock = self.recv_socks.get(port)
        if not sock:
            return
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                self.log(f"UDP Port {port} RX socket closed; exiting thread.")
                break
            except Exception as e:
                self.log(f"UDP Port {port} RX error: {e}")
                with self.lock:
                    self.port_counters[port]["Errors"] += 1
                continue
            if self.var_latency.get():
                if data.startswith(b"HELLO:"):
                    try:
                        sock.sendto(b"HELLO_ACK:" + data.split(b":", 1)[1], addr)
                        self.log(f"UDP Port {port}: Received HELLO; replied with HELLO_ACK.")
                    except Exception as e:
                        self.log(f"Error replying HELLO_ACK from UDP port {port}: {e}")
                    continue
                elif data.startswith(b"HELLO_ACK:"):
                    try:
                        sent_timestamp = float(data.split(b":", 1)[1])
                        rtt = time.perf_counter() - sent_timestamp
                        self.log(f"UDP Port {port} Latency: RTT ~ {rtt*1000:.2f} ms")
                    except Exception as e:
                        self.log(f"Error computing latency at UDP port {port}: {e}")
                    continue
            if self.verify_packet(data, port):
                with self.lock:
                    self.port_counters[port]["RX"] += 1
                    self.port_counters[port]["Bytes_RX"] += len(data)
            else:
                with self.lock:
                    self.port_counters[port]["Errors"] += 1

    # ----- TCP Methods -----
    def start_tcp_sending_threads(self):
        pps = self.packets_per_second.get()
        if pps < 1:
            self.log(f"TCP: Packets per second too low ({pps}). Using 1 PPS.")
            pps = 1
            self.packets_per_second.set(1)
        max_pkts = self.max_packets.get()
        for port in PORT_NAMES:
            if self.port_tx_vars[port].get():
                thread = threading.Thread(target=self.tcp_packet_sending_worker, args=(port, pps, max_pkts))
                thread.daemon = True
                self.tcp_sending_threads[port] = thread
                thread.start()
                self.log(f"Started TCP TX thread for port {port}.")

    def tcp_packet_sending_worker(self, port, pps, max_pkts):
        while self.running:
            # Check interface state before (re)connecting
            stats = psutil.net_if_stats()
            iface_str = self.port_comboboxes[port].get()
            iface_name = iface_str.split(" - ")[0] if iface_str and " - " in iface_str else None
            if not iface_name or iface_name not in stats or not stats[iface_name].isup or stats[iface_name].speed == 0:
                self.log(f"TCP Port {port} TX: Interface {iface_name} is down. Waiting for reconnection.")
                time.sleep(1)
                with self.lock:
                    self.port_counters[port]["Lost"] += 1
                continue

            # Attempt to establish TCP connections to all selected RX ports
            connections = {}
            for dport in PORT_NAMES:
                if self.port_rx_vars[dport].get():
                    dest_iface = self.port_comboboxes[dport].get().split(" - ")
                    dest_ip = dest_iface[1].strip() if len(dest_iface) > 1 else "0.0.0.0"
                    dest_port = self.receiver_ports[dport]
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        # Set SO_DONTROUTE to force physical routing.
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_DONTROUTE, 1)
                        iface = self.port_comboboxes[port].get().split(" - ")
                        iface_ip = iface[1].strip() if len(iface) > 1 else "0.0.0.0"
                        s.bind((iface_ip, 0))
                        self.bind_to_interface(s, port)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                        s.connect((dest_ip, dest_port))
                        connections[dport] = s
                        self.log(f"TCP: Port {port} connected to {dport} at {dest_ip}:{dest_port}.")
                    except Exception as e:
                        self.log(f"TCP: Error connecting from port {port} to {dport} ({dest_ip}:{dest_port}): {e}")
            if not connections:
                # If no connections could be made, wait and retry.
                time.sleep(1)
                continue

            interval = 1.0 / pps
            next_send_time = time.perf_counter()
            while self.running:
                # Check interface state before sending
                stats = psutil.net_if_stats()
                iface_str = self.port_comboboxes[port].get()
                iface_name = iface_str.split(" - ")[0] if iface_str and " - " in iface_str else None
                if not iface_name or iface_name not in stats or not stats[iface_name].isup or stats[iface_name].speed == 0:
                    self.log(f"TCP Port {port} TX: Interface {iface_name} is down. Waiting for reconnection.")
                    time.sleep(1)
                    with self.lock:
                        self.port_counters[port]["Lost"] += 1
                    continue

                now = time.perf_counter()
                if now >= next_send_time:
                    seq = self.port_seq[port]
                    packet = self.generate_packet(seq)
                    for dport, conn in list(connections.items()):
                        try:
                            conn.sendall(packet)
                        except Exception as e:
                            with self.lock:
                                self.port_counters[port]["Errors"] += 1
                                self.port_counters[port]["Lost"] += 1
                            self.log(f"TCP: Error sending from port {port} to {dport}: {e}")
                            # Remove this connection so we can try to reconnect later.
                            try:
                                conn.shutdown(socket.SHUT_RDWR)
                            except Exception:
                                pass
                            try:
                                conn.close()
                            except Exception:
                                pass
                            del connections[dport]
                    with self.lock:
                        self.port_counters[port]["TX"] += 1
                    next_send_time += interval
                    self.port_seq[port] += 1
                    if max_pkts > 0 and self.port_seq[port] >= max_pkts:
                        self.log(f"TCP: Port {port} reached max packet count ({max_pkts}).")
                        self.mark_tx_finished(port)
                        break
                else:
                    remaining = next_send_time - now
                    while remaining > 0 and self.running:
                        time.sleep(min(0.1, remaining))
                        remaining = next_send_time - time.perf_counter()
                # If all connections are lost, break and attempt to reconnect.
                if not connections:
                    self.log(f"TCP: All connections from port {port} lost. Reconnecting...")
                    break
            # Close any remaining connections before retrying.
            for conn in connections.values():
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass

    def start_tcp_receiver_threads(self):
        for port in PORT_NAMES:
            if self.port_rx_vars[port].get():
                thread = threading.Thread(target=self.tcp_receive_worker, args=(port,))
                thread.daemon = True
                self.tcp_receiver_threads[port] = thread
                thread.start()
                self.log(f"Started TCP RX thread for port {port}.")

    def tcp_receive_worker(self, port):
        iface = self.port_comboboxes[port].get()
        iface_parts = iface.split(" - ")
        iface_ip = iface_parts[1].strip() if len(iface_parts) > 1 else "0.0.0.0"
        recv_port = self.receiver_ports[port]
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((iface_ip, recv_port))
            self.bind_to_interface(server, port)
            server.listen(5)
            server.settimeout(1.0)
            self.tcp_recv_socks[port] = server
            self.log(f"TCP: Port {port} RX server listening on {iface_ip}:{recv_port}.")
        except Exception as e:
            self.log(f"TCP: Error binding RX server on port {port}: {e}")
            return
        while self.running:
            try:
                conn, addr = server.accept()
                self.log(f"TCP: Port {port} accepted connection from {addr}.")
                handler = threading.Thread(target=self.tcp_receive_handler, args=(port, conn))
                handler.daemon = True
                handler.start()
            except socket.timeout:
                continue
            except OSError as e:
                # If the socket is closed, break out of the loop gracefully.
                if (getattr(e, 'winerror', None) == 10038) or (getattr(e, 'errno', None) == 10038):
                    break
                else:
                    self.log(f"TCP: Port {port} accept error: {e}")
                    break
            except Exception as e:
                self.log(f"TCP: Port {port} accept error: {e}")
                break
        try:
            server.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            server.close()
        except Exception:
            pass

    def tcp_receive_handler(self, port, conn):
        while self.running:
            try:
                data = conn.recv(65535)
                if not data:
                    break
                with self.lock:
                    self.port_counters[port]["RX"] += 1
                    self.port_counters[port]["Bytes_RX"] += len(data)
            except Exception as e:
                self.log(f"TCP: Port {port} receive error: {e}")
                break
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    def verify_packet(self, data, port):
        if len(data) < 8:
            self.log(f"Port {port} received packet too short: {len(data)} bytes.")
            return False
        payload = data[:-4]
        received_crc = struct.unpack("I", data[-4:])[0]
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if calc_crc != received_crc:
            self.log(f"Port {port} CRC mismatch: calculated {calc_crc}, received {received_crc}.")
            return False
        seq = struct.unpack("I", payload[:4])[0]
        body = payload[4:]
        if self.var_hmac.get():
            if not body.startswith(b"HMAC:"):
                self.log(f"Port {port} missing HMAC header.")
                return False
            try:
                hmac_field, rest = body.split(b";", 1)
                received_hmac = hmac_field.split(b":", 1)[1]
            except Exception as e:
                self.log(f"Port {port} error parsing HMAC header: {e}")
                return False
            computed_hmac = hmac.new(SECRET_KEY, rest, hashlib.sha256).hexdigest().encode("utf-8")
            if computed_hmac != received_hmac:
                self.log(f"Port {port} HMAC mismatch: computed {computed_hmac.decode()}, received {received_hmac.decode()}.")
                return False
            body = rest
        with self.lock:
            last_seq = self.port_last_seq[port]
            if seq > last_seq:
                gap = seq - (last_seq + 1)
                if gap > 0:
                    self.port_counters[port]["Lost"] += gap
                    self.log(f"Port {port} detected {gap} lost packet(s).")
                self.port_last_seq[port] = seq
        return True

    # -------------------------- Statistics & Utility Methods --------------------------
    def update_counters_table(self):
        with self.lock:
            for port in PORT_NAMES:
                self.counter_labels[port]['TX'].config(text=str(self.port_counters[port]["TX"]))
                self.counter_labels[port]['RX'].config(text=str(self.port_counters[port]["RX"]))
                self.counter_labels[port]['Errors'].config(text=str(self.port_counters[port]["Errors"]))
                self.counter_labels[port]['Lost'].config(text=str(self.port_counters[port]["Lost"]))
        self.after_counters_id = self.root.after(500, self.update_counters_table)

    def update_speed(self):
        with self.lock:
            total_bytes = sum(self.port_counters[port]["Bytes_RX"] for port in PORT_NAMES)
        current_time = time.perf_counter()
        elapsed = current_time - self.start_time

        # Calculate instantaneous speed using the bytes received since last check.
        delta_bytes = total_bytes - self.last_total_bytes
        delta_time = current_time - self.last_time
        # Clamp delta_time to at least 1 second to prevent unrealistically high speeds.
        effective_delta_time = max(delta_time, 1.0)
        inst_speed = (delta_bytes * 8) / (effective_delta_time * 1e6)

        # Update max speed if instantaneous speed exceeds previous maximum.
        if inst_speed > self.max_speed_record:
            self.max_speed_record = inst_speed

        # Compute average speed over the entire period.
        avg_speed = (total_bytes * 8) / (elapsed * 1e6) if elapsed > 0 else 0

        self.total_received_label.config(text=self.human_readable(total_bytes))
        self.max_speed_label.config(text=self.format_speed(self.max_speed_record))
        self.average_speed_label.config(text=self.format_speed(avg_speed))

        self.last_total_bytes = total_bytes
        self.last_time = current_time

        self.after_speed_id = self.root.after(1000, self.update_speed)

    def human_readable(self, num_bytes):
        units = ["B", "KB", "MB", "GB", "TB"]
        index = 0
        value = float(num_bytes)
        while value >= 1024 and index < len(units) - 1:
            value /= 1024.0
            index += 1
        return f"{value:.4g} {units[index]}"

    def format_speed(self, speed_mbps):
        if speed_mbps < 1000:
            return f"{speed_mbps:.2f} Mbps"
        else:
            return f"{(speed_mbps / 1000):.2f} Gbps"

    def disable_widgets(self):
        for widget in self.interactive_widgets:
            widget.config(state="disabled")

    def enable_widgets(self):
        for widget in self.interactive_widgets:
            widget.config(state="normal")

    def clear_all(self):
        self.debug_text.config(state="normal")
        self.debug_text.delete("1.0", tk.END)
        self.debug_text.config(state="disabled")
        with self.lock:
            for port in PORT_NAMES:
                self.port_counters[port] = {"TX": 0, "RX": 0, "Errors": 0, "Lost": 0,
                                            "Bytes_TX": 0, "Bytes_RX": 0}
                self.port_seq[port] = 0
                self.port_last_seq[port] = -1
            self.max_speed_record = 0.0
        self.start_time = time.perf_counter()
        self.last_total_bytes = 0
        self.last_time = self.start_time
        self.random_payload = None

    # -------------------------- Improved Stop Method with Bounded Joins --------------------------
    def stop_all_activity(self):
        """
        Stop all TX/RX threads (both UDP and TCP) and close all sockets using bounded join timeouts.
        The displayed counter numbers remain until the user presses Clear.
        """
        self.start_button.grid()
        self.clear_button.grid()
        self.enable_widgets()
        self.stop_button.config(state="disabled")
        self.update_user_settings()
        self.save_config()

        if not self.running:
            return

        self.log("Stop command received. Stopping all TX/RX threads and closing sockets.")
        self.running = False

        # 1. Close UDP sockets
        for sock in list(self.sending_socks.values()):
            try:
                sock.close()
            except Exception as e:
                self.log(f"Error closing UDP TX socket: {e}")
        self.sending_socks.clear()

        for sock in list(self.recv_socks.values()):
            try:
                sock.close()
            except Exception as e:
                self.log(f"Error closing UDP RX socket: {e}")
        self.recv_socks.clear()

        # 2. Join UDP threads with bounded time
        for t in list(self.sending_threads.values()):
            total_time = 0.0
            while t.is_alive() and total_time < 2.0:
                t.join(timeout=0.1)
                total_time += 0.1
            if t.is_alive():
                self.log("Warning: A UDP TX thread did not exit within 2 seconds.")
        self.sending_threads.clear()

        for t in list(self.receiver_threads.values()):
            total_time = 0.0
            while t.is_alive() and total_time < 2.0:
                t.join(timeout=0.1)
                total_time += 0.1
            if t.is_alive():
                self.log("Warning: A UDP RX thread did not exit within 2 seconds.")
        self.receiver_threads.clear()

        # 3. Close TCP sockets
        for port_dict in self.tcp_sending_socks.values():
            for sock in port_dict.values():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception as e:
                    self.log(f"Error closing TCP TX socket: {e}")
        self.tcp_sending_socks.clear()

        for sock in list(self.tcp_recv_socks.values()):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception as e:
                self.log(f"Error closing TCP RX server socket: {e}")
        self.tcp_recv_socks.clear()

        # 4. Join TCP threads with bounded time
        for t in list(self.tcp_sending_threads.values()):
            total_time = 0.0
            while t.is_alive() and total_time < 2.0:
                t.join(timeout=0.1)
                total_time += 0.1
            if t.is_alive():
                self.log("Warning: A TCP TX thread did not exit within 2 seconds.")
        self.tcp_sending_threads.clear()

        for t in list(self.tcp_receiver_threads.values()):
            total_time = 0.0
            while t.is_alive() and total_time < 2.0:
                t.join(timeout=0.1)
                total_time += 0.1
            if t.is_alive():
                self.log("Warning: A TCP RX thread did not exit within 2 seconds.")
        self.tcp_receiver_threads.clear()

        self.log("All TX/RX threads stopped.")
        self.reset_internal_state()

    def on_close(self):
        self.log("Exiting application...")
        try:
            if self.after_speed_id:
                self.root.after_cancel(self.after_speed_id)
            if self.after_counters_id:
                self.root.after_cancel(self.after_counters_id)
        except Exception as e:
            self.log(f"Error cancelling callbacks: {e}")
        self.stop_all_activity()
        self.root.quit()
        self.root.destroy()
        os._exit(0)

# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("The 'psutil' library is required but not installed.\nInstall it using 'pip install psutil'.")
        sys.exit(1)
    root = tk.Tk()
    root.resizable(True, True)
    app = PacketGeneratorApp(root)
    root.mainloop()
