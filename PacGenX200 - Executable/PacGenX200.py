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
import sys
import uuid
import hmac
import hashlib

# Shared secret key for HMAC signing
SECRET_KEY = b'secret-key'

# Maximum UDP payload size (in bytes)
MAX_UDP_PAYLOAD = 65507  # Maximum bytes a UDP datagram can carry

# Configuration file and constants
CONFIG_FILE = "packet_gen_config.json"
MAX_PREVIEW_LENGTH = 300

# Logical port names
PORT_NAMES = ['A', 'B', 'C', 'D']

class PacketGeneratorApp:
    """
    Enterprise-level Packet Generator with persistent settings and four configurable ports.
    (Detailed description omitted for brevity.)
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Generator (Enterprise)")
        self.root.geometry("1300x850")

        # Define target_port BEFORE calling any dependent methods.
        self.target_port = tk.IntVar(value=12345)

        # Configure main window (top: controls/status, bottom: debug console)
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

        self.running = False

        self.port_counters = {port: {"TX": 0, "RX": 0, "Errors": 0, "Lost": 0,
                                      "Bytes_TX": 0, "Bytes_RX": 0} for port in PORT_NAMES}
        self.port_seq = {port: 0 for port in PORT_NAMES}
        self.port_last_seq = {port: -1 for port in PORT_NAMES}

        self.sending_socks = {}
        self.sending_threads = {}
        self.recv_socks = {}
        self.receiver_threads = {}

        self.lock = threading.Lock()

        self.after_speed_id = None
        self.after_counters_id = None

        self.default_settings = {
            "target_port": 12345,
            "packet_size": 32768,
            "packets_per_second": 1000,
            "max_packets": 1000,  # 0 not allowed
            "use_handshake": False,
            "use_start_delay": False,
            "use_verbose": False,
            "add_protocol_version": False,
            "add_source_mac": False,
            "add_unique_id": False,
            "add_payload_signature": False,
            "max_packet_size": MAX_UDP_PAYLOAD,  # enforce system UDP limit
            "min_packet_size": 4000,
            "max_packs_per_sec": 4000,
            "min_packs_per_sec": 1
        }
        self.user_settings = self.load_config()
        self.setup_receiver_ports()
        self.status_text = tk.StringVar(value="Status: Ready")
        self.max_speed_record = 0.0
        self.port_comboboxes = {}
        self.port_tx_vars = {}
        self.port_rx_vars = {}
        self.counter_labels = {port: {} for port in PORT_NAMES}
        self.link_leds = {}
        self.tx_finished = {}
        self.start_time = time.perf_counter()

        # New feature variables:
        self.var_random = tk.BooleanVar(value=False)
        self.random_payload = None
        self.var_latency = tk.BooleanVar(value=False)
        self.var_hmac = tk.BooleanVar(value=False)
        # New extended options:
        self.var_ext_a = tk.BooleanVar(value=False)  # adds 50 bytes overhead
        self.var_ext_b = tk.BooleanVar(value=False)  # adds 100 bytes overhead

        self.create_widgets()
        self.detect_network_interfaces()
        self.apply_loaded_settings()

        self.log("Welcome to Packet Generator (Enterprise)!")
        if os.path.isfile(CONFIG_FILE):
            self.log("Your settings have been loaded from configuration.")
        else:
            self.log("No config found; using defaults.")

        self.update_speed()
        self.update_counters_table()
        self.update_link_status()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.maximize_window()

    def setup_receiver_ports(self):
        base = self.target_port.get()
        self.receiver_ports = {}
        for i, port in enumerate(PORT_NAMES):
            self.receiver_ports[port] = base + i

    def load_config(self):
        if os.path.isfile(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                for k, v in self.default_settings.items():
                    data.setdefault(k, v)
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

    def validate_fields(self):
        try:
            size = int(self.packet_size.get())
        except Exception:
            size = self.default_settings["packet_size"]
        if size < self.default_settings["min_packet_size"]:
            size = self.default_settings["min_packet_size"]
        if size > self.default_settings["max_packet_size"]:
            size = self.default_settings["max_packet_size"]
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

    def compute_header_overhead(self):
        """
        Compute the total header overhead in bytes.
        Includes:
          - 4 bytes for the Sequence Number.
          - Optional fields if enabled.
          - Extended Option A (+50 bytes) and Extended Option B (+100 bytes) if enabled.
          - If HMAC is enabled, adds the length of the HMAC header ("HMAC:" + 64 hex digits + ";" = 5+64+1 = 70 bytes).
        """
        overhead = 4  # Sequence Number
        temp = b""
        if self.var_protocol_version.get():
            temp += b"Protocol-Version:1.0;"
        if self.var_source_mac.get():
            # Assume MAC is 17 characters (e.g. "AA-BB-CC-DD-EE-FF")
            temp += f"Source-MAC:{'AA-BB-CC-DD-EE-FF'};".encode("utf-8")
        if self.var_unique_id.get():
            # UUID string length is 36 characters
            temp += f"UUID:{'0'*36};".encode("utf-8")
        if self.var_payload_signature.get():
            # Placeholder length for payload signature
            temp += f"Payload-CRC32:{0};".encode("utf-8")
        overhead += len(temp)
        if self.var_hmac.get():
            # HMAC header: "HMAC:" + 64 hex digits + ";" = 5 + 64 + 1 = 70 bytes
            overhead += 70
        if self.var_ext_a.get():
            overhead += 50
        if self.var_ext_b.get():
            overhead += 100
        return overhead

    def update_header_length_label(self):
        overhead = self.compute_header_overhead()
        # The total packet will have: overhead + filler + 4 (CRC)
        # Thus, maximum filler allowed = MAX_UDP_PAYLOAD - (overhead + 4)
        max_filler = MAX_UDP_PAYLOAD - (overhead + 4)
        self.header_length_label.config(text=f"Protocol Header Overhead: {overhead} bytes | Max Filler: {max_filler} bytes")

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

    def log(self, message):
        if not self.var_verbose.get():
            return
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        self.debug_text.config(state="normal")
        self.debug_text.insert("end", full_message + "\n")
        self.debug_text.see("end")
        self.debug_text.config(state="disabled")

    def on_close(self):
        self.log("Exiting application...")
        try:
            if self.after_speed_id:
                self.root.after_cancel(self.after_speed_id)
            if self.after_counters_id:
                self.root.after_cancel(self.after_counters_id)
        except Exception as e:
            self.log(f"Error cancelling callbacks: {e}")
        self.update_user_settings()
        self.save_config()
        self.stop_all_activity()
        self.root.quit()
        self.root.destroy()
        os._exit(0)

    def create_widgets(self):
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
        self.bottom_frame = ttk.Frame(self.root)
        self.bottom_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.top_frame.grid_columnconfigure(0, weight=1)
        self.top_frame.grid_columnconfigure(1, weight=1)
        self.top_frame.grid_rowconfigure(0, weight=1)

        self.controls_frame = ttk.Frame(self.top_frame)
        self.controls_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.controls_frame.grid_rowconfigure(4, weight=1)
        self.create_controls(self.controls_frame)

        self.status_frame = ttk.Frame(self.top_frame)
        self.status_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.status_frame.grid_rowconfigure(2, weight=1)
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
        ttk.Label(packet_frame, text="Packet Size (Bytes):", anchor="w").grid(row=0, column=0, padx=5, pady=3)
        self.packet_size = tk.IntVar(value=32768)
        self.packet_size_entry = ttk.Entry(packet_frame, textvariable=self.packet_size)
        self.packet_size_entry.grid(row=0, column=1, padx=5, pady=3, sticky="ew")
        ttk.Label(packet_frame, text="Packets per Second:", anchor="w").grid(row=0, column=2, padx=5, pady=3)
        self.packets_per_second = tk.IntVar(value=1000)
        self.packets_per_second_entry = ttk.Entry(packet_frame, textvariable=self.packets_per_second)
        self.packets_per_second_entry.grid(row=0, column=3, padx=5, pady=3, sticky="ew")
        ttk.Label(packet_frame, text="Max Packets (Required, >0):", anchor="w").grid(row=1, column=0, padx=5, pady=3)
        self.max_packets = tk.IntVar(value=1000)
        self.max_packets_entry = ttk.Entry(packet_frame, textvariable=self.max_packets)
        self.max_packets_entry.grid(row=1, column=1, padx=5, pady=3, sticky="ew")

        features_frame = ttk.LabelFrame(parent, text="Features")
        features_frame.pack(fill="x", padx=5, pady=5)
        self.var_handshake = tk.BooleanVar(value=False)
        self.var_start_delay = tk.BooleanVar(value=False)
        self.var_verbose = tk.BooleanVar(value=False)
        self.handshake_chk = ttk.Checkbutton(features_frame, text="Enable Handshake", variable=self.var_handshake)
        self.handshake_chk.grid(row=0, column=0, padx=5, pady=3, sticky="w")
        self.delay_chk = ttk.Checkbutton(features_frame, text="Start Delay (3s)", variable=self.var_start_delay)
        self.delay_chk.grid(row=0, column=1, padx=5, pady=3, sticky="w")
        self.verbose_chk = ttk.Checkbutton(features_frame, text="Verbose Logging", variable=self.var_verbose)
        self.verbose_chk.grid(row=0, column=2, padx=5, pady=3, sticky="w")
        self.var_protocol_version = tk.BooleanVar(value=False)
        self.var_source_mac = tk.BooleanVar(value=False)
        self.var_unique_id = tk.BooleanVar(value=False)
        self.var_payload_signature = tk.BooleanVar(value=False)
        self.protocol_version_chk = ttk.Checkbutton(features_frame, text="Add Protocol Version", variable=self.var_protocol_version)
        self.protocol_version_chk.grid(row=1, column=0, padx=5, pady=3, sticky="w")
        self.source_mac_chk = ttk.Checkbutton(features_frame, text="Add Source MAC Address", variable=self.var_source_mac)
        self.source_mac_chk.grid(row=1, column=1, padx=5, pady=3, sticky="w")
        self.unique_id_chk = ttk.Checkbutton(features_frame, text="Add Unique Identifier", variable=self.var_unique_id)
        self.unique_id_chk.grid(row=1, column=2, padx=5, pady=3, sticky="w")
        self.payload_signature_chk = ttk.Checkbutton(features_frame, text="Add Payload Signature", variable=self.var_payload_signature)
        self.payload_signature_chk.grid(row=1, column=3, padx=5, pady=3, sticky="w")
        self.var_random = tk.BooleanVar(value=False)
        self.random_chk = ttk.Checkbutton(features_frame, text="Enable Random Payload", variable=self.var_random)
        self.random_chk.grid(row=2, column=0, padx=5, pady=3, sticky="w")
        self.var_latency = tk.BooleanVar(value=False)
        self.latency_chk = ttk.Checkbutton(features_frame, text="Enable Latency Measurement", variable=self.var_latency)
        self.latency_chk.grid(row=2, column=1, padx=5, pady=3, sticky="w")
        self.var_hmac = tk.BooleanVar(value=False)
        self.hmac_chk = ttk.Checkbutton(features_frame, text="Enable HMAC Signing", variable=self.var_hmac)
        self.hmac_chk.grid(row=2, column=2, padx=5, pady=3, sticky="w")
        # New extended options
        self.var_ext_a = tk.BooleanVar(value=False)
        self.ext_a_chk = ttk.Checkbutton(features_frame, text="Enable Extended Option A (+50 bytes)", variable=self.var_ext_a)
        self.ext_a_chk.grid(row=3, column=0, padx=5, pady=3, sticky="w")
        self.var_ext_b = tk.BooleanVar(value=False)
        self.ext_b_chk = ttk.Checkbutton(features_frame, text="Enable Extended Option B (+100 bytes)", variable=self.var_ext_b)
        self.ext_b_chk.grid(row=3, column=1, padx=5, pady=3, sticky="w")
        # New: Header overhead label (shows header overhead and max filler available)
        self.header_length_label = ttk.Label(features_frame, text="Protocol Header Overhead: 0 bytes | Max Filler: 0 bytes")
        self.header_length_label.grid(row=4, column=0, columnspan=4, padx=5, pady=3, sticky="w")
        for var in (self.var_protocol_version, self.var_source_mac, self.var_unique_id,
                    self.var_payload_signature, self.var_hmac, self.var_ext_a, self.var_ext_b):
            var.trace_add("write", lambda *args: self.update_header_length_label())

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
        overhead = self.compute_header_overhead()
        max_filler = MAX_UDP_PAYLOAD - (overhead + 4)  # 4 bytes for the final CRC
        self.header_length_label.config(text=f"Protocol Header Overhead: {overhead} bytes | Max Filler: {max_filler} bytes")

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
            color = "red"
            if iface_name and iface_name in stats and stats[iface_name].isup and stats[iface_name].speed > 0:
                if (self.running and self.port_tx_vars[port].get() and 
                    port in self.sending_threads and self.sending_threads[port].is_alive()):
                    color = "yellow"
                else:
                    color = "green"
            canvas = self.link_leds[port]
            canvas.delete("all")
            canvas.create_oval(2, 2, 18, 18, fill=color, outline="black")
        self.root.after(2000, self.update_link_status)

    def start_all(self):
        if self.running:
            self.log("Already running. Start command ignored.")
            return
        max_pkts = int(self.max_packets.get())
        if any(self.port_tx_vars[port].get() and self.port_seq[port] >= max_pkts for port in PORT_NAMES):
            self.clear_all()
        self.validate_fields()
        self.update_user_settings()
        self.start_button.grid_remove()
        self.clear_button.grid_remove()
        self.stop_button.config(state="normal")
        self.running = True
        self.tx_finished = {port: False for port in PORT_NAMES if self.port_tx_vars[port].get()}
        self.log("Start button pressed. Preparing TX/RX on selected ports.")
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
        self.start_sending_threads()
        self.start_receiver_threads()

    def send_handshake_with_latency(self):
        for port in PORT_NAMES:
            if self.port_tx_vars[port].get():
                iface_info = self.port_comboboxes[port].get().split(" - ")
                sender_ip = iface_info[1].strip() if len(iface_info) > 1 else "0.0.0.0"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((sender_ip, 0))
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

    def start_sending_threads(self):
        pps = self.packets_per_second.get()
        if pps < 1:
            self.log(f"Packets per second too low ({pps}). Using 1 PPS.")
            pps = 1
            self.packets_per_second.set(1)
        max_pkts = self.max_packets.get()
        for port in PORT_NAMES:
            if self.port_tx_vars[port].get():
                iface = self.port_comboboxes[port].get()
                iface_ip = iface.split(" - ")[1].strip() if iface and len(iface.split(" - ")) > 1 else "0.0.0.0"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((iface_ip, 0))
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                    self.sending_socks[port] = sock
                    self.log(f"Port {port} TX socket bound on {iface_ip}.")
                except Exception as e:
                    self.log(f"Error binding TX socket on port {port}: {e}")
                    continue
                thread = threading.Thread(target=self.packet_sending_worker_port,
                                          args=(port, pps, max_pkts))
                self.sending_threads[port] = thread
                thread.start()
                self.log(f"Started TX thread for port {port}.")

    def packet_sending_worker_port(self, port, pps, max_pkts):
        interval = 1.0 / pps
        next_send_time = time.perf_counter()
        while self.running:
            now = time.perf_counter()
            if now >= next_send_time:
                iface_str = self.port_comboboxes[port].get()
                iface_name = iface_str.split(" - ")[0] if iface_str and " - " in iface_str else None
                stats = psutil.net_if_stats()
                if iface_name and iface_name in stats and (not stats[iface_name].isup or stats[iface_name].speed == 0):
                    self.log(f"Port {port} TX: local interface {iface_name} is down. Skipping transmission.")
                    next_send_time += interval
                    self.port_seq[port] += 1
                    continue
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
                                    self.log(f"Port {port} TX error sending to port {dport} ({dest_ip}:{dest_port}): {e}")
                            else:
                                self.log(f"Skipping sending to port {dport} because interface {dest_iface_name} is down.")
                    with self.lock:
                        self.port_counters[port]["TX"] += 1
                        self.port_counters[port]["Bytes_TX"] += total_bytes_sent
                except Exception as e:
                    with self.lock:
                        self.port_counters[port]["Errors"] += 1
                    self.log(f"Port {port} TX error: {e}")
                    break
                next_send_time += interval
                self.port_seq[port] += 1
                if max_pkts > 0 and self.port_seq[port] >= max_pkts:
                    self.log(f"Port {port} reached max packet count ({max_pkts}).")
                    self.mark_tx_finished(port)
                    break
            else:
                remaining = next_send_time - now
                while remaining > 0 and self.running:
                    time.sleep(min(0.1, remaining))
                    remaining = next_send_time - time.perf_counter()

    def mark_tx_finished(self, port):
        with self.lock:
            self.tx_finished[port] = True
            all_finished = all(self.tx_finished.get(p, True) for p in PORT_NAMES if self.port_tx_vars[p].get())
        if all_finished:
            self.log("All enabled TX ports reached max packet count. Waiting for final counter updates...")
            time.sleep(1)
            self.log("Final counters updated. Stopping program.")
            self.stop_all_activity()

    def start_receiver_threads(self):
        for port in PORT_NAMES:
            if self.port_rx_vars[port].get():
                iface = self.port_comboboxes[port].get()
                iface_ip = iface.split(" - ")[1].strip() if iface and len(iface.split(" - ")) > 1 else "0.0.0.0"
                recv_port = self.receiver_ports[port]
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except Exception:
                        pass
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                    sock.settimeout(2)
                    sock.bind((iface_ip, recv_port))
                    self.recv_socks[port] = sock
                    self.log(f"Port {port} RX socket bound on {iface_ip}:{recv_port}.")
                except Exception as e:
                    self.log(f"Error binding RX socket on port {port}: {e}")
                    continue
                thread = threading.Thread(target=self.receive_packets_port, args=(port, recv_port))
                self.receiver_threads[port] = thread
                thread.start()
                self.log(f"Started RX thread for port {port}.")

    def receive_packets_port(self, port, recv_port):
        sock = self.recv_socks.get(port)
        if not sock:
            return
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                self.log(f"Port {port} RX socket closed, exiting thread.")
                break
            except Exception as e:
                self.log(f"Port {port} RX error: {e}")
                with self.lock:
                    self.port_counters[port]["Errors"] += 1
                continue

            if self.var_latency.get():
                if data.startswith(b"HELLO:"):
                    try:
                        sock.sendto(b"HELLO_ACK:" + data.split(b":", 1)[1], addr)
                        self.log(f"Port {port}: Received HELLO; replied with HELLO_ACK.")
                    except Exception as e:
                        self.log(f"Error replying HELLO_ACK from port {port}: {e}")
                    continue
                elif data.startswith(b"HELLO_ACK:"):
                    try:
                        sent_timestamp = float(data.split(b":", 1)[1])
                        rtt = time.perf_counter() - sent_timestamp
                        self.log(f"Port {port} Latency: RTT ~ {rtt*1000:.2f} ms")
                    except Exception as e:
                        self.log(f"Error computing latency at port {port}: {e}")
                    continue

            if self.verify_packet(data, port):
                with self.lock:
                    self.port_counters[port]["RX"] += 1
                    self.port_counters[port]["Bytes_RX"] += len(data)
            else:
                with self.lock:
                    self.port_counters[port]["Errors"] += 1

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

    def generate_packet(self, seq_number):
        user_size = self.packet_size.get()
        min_size = self.default_settings["min_packet_size"]
        max_size = self.default_settings["max_packet_size"]
        if user_size < min_size:
            self.log(f"Packet size too low ({user_size} bytes). Using minimum {min_size} bytes.")
            user_size = min_size
            self.packet_size.set(min_size)
        elif user_size > max_size:
            self.log(f"Packet size too high ({user_size} bytes). Using maximum {max_size} bytes.")
            user_size = max_size
            self.packet_size.set(max_size)
        final_size = min(user_size, MAX_UDP_PAYLOAD)
        seq_header = struct.pack("I", seq_number)
        temp_body = b""
        if self.var_protocol_version.get():
            temp_body += b"Protocol-Version:1.0;"
        if self.var_source_mac.get():
            mac = self.get_source_mac()
            temp_body += f"Source-MAC:{mac};".encode("utf-8")
        if self.var_unique_id.get():
            temp_body += f"UUID:{'0'*36};".encode("utf-8")
        if self.var_payload_signature.get():
            temp_body += f"Payload-CRC32:{0};".encode("utf-8")
        # Calculate maximum allowed body length (packet = seq header (4) + body + CRC (4))
        max_body_length = final_size - 8
        remaining_size = max(0, max_body_length - len(temp_body))
        if self.var_random.get():
            if self.random_payload is None or len(self.random_payload) != remaining_size:
                self.random_payload = os.urandom(remaining_size)
            temp_body += self.random_payload
        else:
            temp_body += b"X" * remaining_size
        if self.var_hmac.get():
            computed_hmac = hmac.new(SECRET_KEY, temp_body, hashlib.sha256).hexdigest()
            body = f"HMAC:{computed_hmac};".encode("utf-8") + temp_body
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
                        if addr.family == psutil.AF_LINK:
                            mac = addr.address
                            if mac:
                                return mac.upper().replace(":", "-")
                    break
                except Exception as e:
                    self.log(f"Error retrieving MAC for port {port}: {e}")
                    break
        return "00-00-00-00-00-00"

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
        elapsed = time.perf_counter() - self.start_time
        avg_speed = (total_bytes * 8) / (elapsed * 1e6) if elapsed > 0 else 0
        self.total_received_label.config(text=self.human_readable(total_bytes))
        if avg_speed > self.max_speed_record:
            self.max_speed_record = avg_speed
        self.max_speed_label.config(text=self.format_speed(self.max_speed_record))
        self.average_speed_label.config(text=self.format_speed(avg_speed))
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
        self.random_payload = None

    def stop_all_activity(self):
        if self.running:
            self.log("Stop command received. Stopping all TX/RX threads and closing sockets.")
            self.log("Stop process initiated. Waiting for threads to finish...")
        self.running = False
        for t in self.sending_threads.values():
            if t.is_alive():
                t.join(timeout=2)
        for t in self.receiver_threads.values():
            if t.is_alive():
                t.join(timeout=2)
        for sock in self.sending_socks.values():
            try:
                sock.close()
            except Exception as e:
                self.log(f"Error closing TX socket: {e}")
        self.sending_socks.clear()
        for sock in self.recv_socks.values():
            try:
                sock.close()
            except Exception as e:
                self.log(f"Error closing RX socket: {e}")
        self.recv_socks.clear()
        self.start_button.grid()
        self.clear_button.grid()
        self.enable_widgets()
        self.stop_button.config(state="disabled")

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
