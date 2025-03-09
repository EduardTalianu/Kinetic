import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import datetime

class AgentConfigTab:
    def __init__(self, parent, campaign_tab, logger):
        self.frame = ttk.Frame(parent)
        self.campaign_tab = campaign_tab  # Reference to campaign tab to access/update campaign settings
        self.logger = logger
        
        # Initialize variables that will be moved from campaign tab
        self.beacon_period_var = tk.StringVar(value="3")  # Default value
        self.kill_date_var = tk.StringVar()
        self.jitter_percentage_var = tk.StringVar(value="20")  # Default jitter is 20%
        
        # Initialize new configurable options
        self.user_agent_var = tk.StringVar(value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
        self.max_sleep_var = tk.StringVar(value="10")  # Default 10 minutes
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.proxy_enabled_var = tk.BooleanVar(value=False)
        self.proxy_type_var = tk.StringVar(value="system")  # Default to system proxy
        self.proxy_server_var = tk.StringVar()
        self.proxy_port_var = tk.StringVar()
        
        # Set the default kill date (10 days in the future)
        future_date = datetime.date.today() + datetime.timedelta(days=10)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
        
        # Create the UI components
        self.create_widgets()
    
    def create_widgets(self):
        """Create the UI components for agent configuration"""
        main_frame = ttk.Frame(self.frame, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title with explanation
        title_label = ttk.Label(main_frame, text="Agent Configuration", font=("Arial", 12, "bold"))
        title_label.pack(anchor=tk.W, pady=(0, 10))
        
        description = (
            "Configure parameters that affect agent behavior. These settings will be applied "
            "when generating new agents."
        )
        desc_label = ttk.Label(main_frame, text=description, wraplength=600, justify=tk.LEFT)
        desc_label.pack(anchor=tk.W, pady=(0, 15))

        # Create frames for different configuration sections
        beacon_frame = ttk.LabelFrame(main_frame, text="Beacon Settings")
        beacon_frame.pack(fill=tk.X, pady=10)
        
        security_frame = ttk.LabelFrame(main_frame, text="Security Settings")
        security_frame.pack(fill=tk.X, pady=10)
        
        fallback_frame = ttk.LabelFrame(main_frame, text="Fallback & Recovery")
        fallback_frame.pack(fill=tk.X, pady=10)
        
        # New: Communication & Identity frame
        comm_frame = ttk.LabelFrame(main_frame, text="Communication & Identity")
        comm_frame.pack(fill=tk.X, pady=10)
        
        # New: Proxy Settings frame
        proxy_frame = ttk.LabelFrame(main_frame, text="Proxy Settings")
        proxy_frame.pack(fill=tk.X, pady=10)
        
        # Beacon Settings
        ttk.Label(beacon_frame, text="Beacon Period (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.beacon_entry = ttk.Entry(beacon_frame, textvariable=self.beacon_period_var, width=10)
        self.beacon_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(beacon_frame, text="How often the agent checks in with the C2 server").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(beacon_frame, text="Jitter Percentage:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        jitter_values = ["0", "10", "20", "30", "40", "50"]
        self.jitter_combo = ttk.Combobox(beacon_frame, textvariable=self.jitter_percentage_var, values=jitter_values, width=8)
        self.jitter_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(beacon_frame, text="Random variation in beacon timing to avoid detection").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Security Settings
        ttk.Label(security_frame, text="Kill Date:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.kill_date_entry = ttk.Entry(security_frame, textvariable=self.kill_date_var, width=15)
        self.kill_date_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(security_frame, text="Date when agent will stop functioning (dd/mm/yyyy)").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Generate a date 30 days from now button
        ttk.Button(security_frame, text="+ 30 Days", command=self.set_30_days_expiry).grid(
            row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Username and Password
        ttk.Label(security_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = ttk.Entry(security_frame, textvariable=self.username_var, width=15)
        self.username_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(security_frame, text="Optional authentication username").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(security_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = ttk.Entry(security_frame, textvariable=self.password_var, width=15, show="*")
        self.password_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(security_frame, text="Optional authentication password").grid(row=2, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Failback & Recovery Settings
        ttk.Label(fallback_frame, text="Max Failures Before Fallback:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_failures_var = tk.StringVar(value="3")  # Default to 3
        self.max_failures_entry = ttk.Entry(fallback_frame, textvariable=self.max_failures_var, width=5)
        self.max_failures_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(fallback_frame, text="Number of failed connections before using fallback paths").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fallback_frame, text="Max Backoff Time (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_backoff_var = tk.StringVar(value="10")  
        self.max_backoff_entry = ttk.Entry(fallback_frame, textvariable=self.max_backoff_var, width=5)
        self.max_backoff_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(fallback_frame, text="Maximum time between reconnection attempts").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fallback_frame, text="Max Random Sleep Time (seconds):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_sleep_entry = ttk.Entry(fallback_frame, textvariable=self.max_sleep_var, width=5)
        self.max_sleep_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(fallback_frame, text="Maximum duration for sleep when not communicating with server").grid(row=2, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Communication & Identity Settings
        ttk.Label(comm_frame, text="User-Agent:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_agent_entry = ttk.Entry(comm_frame, textvariable=self.user_agent_var, width=60)
        self.user_agent_entry.grid(row=0, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # User-Agent presets dropdown
        ttk.Label(comm_frame, text="Presets:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ua_presets = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        ]
        
        self.ua_preset_combo = ttk.Combobox(comm_frame, values=ua_presets, width=57)
        self.ua_preset_combo.grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        self.ua_preset_combo.bind("<<ComboboxSelected>>", self.on_ua_preset_selected)
        
        # Proxy Settings
        self.proxy_check = ttk.Checkbutton(proxy_frame, text="Enable Proxy", variable=self.proxy_enabled_var, command=self.toggle_proxy_options)
        self.proxy_check.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Proxy Type Selection
        ttk.Label(proxy_frame, text="Proxy Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        proxy_types = ["system", "http", "socks4", "socks5"]
        self.proxy_type_combo = ttk.Combobox(proxy_frame, textvariable=self.proxy_type_var, values=proxy_types, width=10, state="disabled")
        self.proxy_type_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(proxy_frame, text="Type of proxy to use ('system' uses Windows/OS settings)").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Proxy Server
        ttk.Label(proxy_frame, text="Proxy Server:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.proxy_server_entry = ttk.Entry(proxy_frame, textvariable=self.proxy_server_var, width=30, state="disabled")
        self.proxy_server_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(proxy_frame, text="Only needed for manual proxy configuration").grid(row=2, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Proxy Port
        ttk.Label(proxy_frame, text="Proxy Port:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.proxy_port_entry = ttk.Entry(proxy_frame, textvariable=self.proxy_port_var, width=10, state="disabled")
        self.proxy_port_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(proxy_frame, text="Port number for the proxy server").grid(row=3, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Buttons for saving and applying configuration
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=15)
        
        ttk.Button(button_frame, text="Save Configuration", command=self.save_configuration).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_to_defaults).pack(side=tk.LEFT, padx=5)
    
    def on_ua_preset_selected(self, event):
        """Update the user agent entry when a preset is selected"""
        selected_ua = self.ua_preset_combo.get()
        if selected_ua:
            self.user_agent_var.set(selected_ua)
    
    def toggle_proxy_options(self):
        """Enable or disable proxy configuration options based on checkbox"""
        state = "normal" if self.proxy_enabled_var.get() else "disabled"
        self.proxy_type_combo.config(state=state)
        
        # Only enable server and port if not system proxy and proxy is enabled
        manual_proxy_state = "normal" if (self.proxy_enabled_var.get() and self.proxy_type_var.get() != "system") else "disabled"
        self.proxy_server_entry.config(state=manual_proxy_state)
        self.proxy_port_entry.config(state=manual_proxy_state)
        
        # Make the type combo update the manual fields when changed
        if state == "normal":
            self.proxy_type_combo.bind("<<ComboboxSelected>>", self.on_proxy_type_changed)
        else:
            self.proxy_type_combo.unbind("<<ComboboxSelected>>")
    
    def on_proxy_type_changed(self, event):
        """Update fields when proxy type changes"""
        manual_proxy_state = "normal" if self.proxy_type_var.get() != "system" else "disabled"
        self.proxy_server_entry.config(state=manual_proxy_state)
        self.proxy_port_entry.config(state=manual_proxy_state)
    
    def sync_from_campaign_tab(self):
        """Sync values from campaign tab to keep compatibility with existing config files"""
        # Load values from any existing configuration first
        campaign_name = ""
        if hasattr(self.campaign_tab, 'entry_campaign'):
            campaign_name = self.campaign_tab.entry_campaign.get().strip()
            
        if campaign_name:
            # Try to load existing agent configuration
            if not self.load_configuration(campaign_name):
                # If no configuration exists, try to get values from config.txt
                campaign_dir = f"{campaign_name}_campaign"
                config_path = os.path.join(campaign_dir, "config.txt")
                
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r') as f:
                            config_lines = f.readlines()
                            
                        # Parse config.txt to extract settings
                        config = {}
                        for line in config_lines:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                config[key.strip()] = value.strip()
                                
                        # Extract beacon period if available
                        if "Beacon Period" in config:
                            beacon_period = config["Beacon Period"]
                            if " sec" in beacon_period:
                                beacon_period = beacon_period.split(" ")[0]
                            self.beacon_period_var.set(beacon_period)
                            
                        # Extract kill date if available
                        if "Kill Date" in config:
                            self.kill_date_var.set(config["Kill Date"])
                            
                    except Exception as e:
                        self.logger(f"Error loading campaign config: {e}")
    
    def save_configuration(self):
        """Save the agent configuration to a file"""
        # Validate inputs before saving
        if not self.validate_inputs():
            return
            
        # Get campaign name to determine save location
        campaign_name = ""
        if hasattr(self.campaign_tab, 'entry_campaign'):
            campaign_name = self.campaign_tab.entry_campaign.get().strip()
        
        if not campaign_name:
            messagebox.showerror("Error", "Please set a campaign name in the Campaign Config tab first.")
            return
        
        # Create configuration dictionary
        config = {
            "beacon_period": self.beacon_period_var.get(),
            "jitter_percentage": self.jitter_percentage_var.get(),
            "kill_date": self.kill_date_var.get(),
            "max_failures_before_fallback": self.max_failures_var.get(),
            "max_backoff_time": self.max_backoff_var.get(),
            "max_sleep_time": self.max_sleep_var.get(),
            "user_agent": self.user_agent_var.get(),
            "username": self.username_var.get(),
            "password": self.password_var.get(),
            "proxy_enabled": self.proxy_enabled_var.get(),
            "proxy_type": self.proxy_type_var.get(),
            "proxy_server": self.proxy_server_var.get(),
            "proxy_port": self.proxy_port_var.get(),
            "last_modified": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save to file in campaign folder
        campaign_folder = f"{campaign_name}_campaign"
        os.makedirs(campaign_folder, exist_ok=True)
        
        config_file = os.path.join(campaign_folder, "agent_config.json")
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=4)
                
            self.logger(f"Agent configuration saved to {config_file}")
            messagebox.showinfo("Success", "Agent configuration saved successfully.")
        except Exception as e:
            self.logger(f"Error saving agent configuration: {e}")
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def load_configuration(self, campaign_name):
        """Load agent configuration from file for a specific campaign"""
        if not campaign_name:
            return False
            
        campaign_folder = f"{campaign_name}_campaign"
        config_file = os.path.join(campaign_folder, "agent_config.json")
        
        if not os.path.exists(config_file):
            self.logger(f"No agent configuration found for campaign {campaign_name}")
            return False
            
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            # Set values from configuration
            if "beacon_period" in config:
                self.beacon_period_var.set(config["beacon_period"])
                
            if "jitter_percentage" in config:
                self.jitter_percentage_var.set(config["jitter_percentage"])
                
            if "kill_date" in config:
                self.kill_date_var.set(config["kill_date"])
                
            if "max_failures_before_fallback" in config:
                self.max_failures_var.set(config["max_failures_before_fallback"])
                
            if "max_backoff_time" in config:
                self.max_backoff_var.set(config["max_backoff_time"])
                
            # Load new configurable settings
            if "max_sleep_time" in config:
                self.max_sleep_var.set(config["max_sleep_time"])
                
            if "user_agent" in config:
                self.user_agent_var.set(config["user_agent"])
                
            if "username" in config:
                self.username_var.set(config["username"])
                
            if "password" in config:
                self.password_var.set(config["password"])
                
            # Proxy settings
            if "proxy_enabled" in config:
                self.proxy_enabled_var.set(config["proxy_enabled"])
                self.toggle_proxy_options()
                
            if "proxy_type" in config:
                self.proxy_type_var.set(config["proxy_type"])
                
            if "proxy_server" in config:
                self.proxy_server_var.set(config["proxy_server"])
                
            if "proxy_port" in config:
                self.proxy_port_var.set(config["proxy_port"])
                
            # Update UI state based on loaded values
            self.toggle_proxy_options()
                
            self.logger(f"Loaded agent configuration from {config_file}")
            return True
        except Exception as e:
            self.logger(f"Error loading agent configuration: {e}")
            return False
    
    def reset_to_defaults(self):
        """Reset all values to defaults"""
        self.beacon_period_var.set("5")
        self.jitter_percentage_var.set("20")
        self.max_failures_var.set("3")
        self.max_backoff_var.set("300")
        self.max_sleep_var.set("600")
        self.user_agent_var.set("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
        self.username_var.set("")
        self.password_var.set("")
        self.proxy_enabled_var.set(False)
        self.proxy_type_var.set("system")
        self.proxy_server_var.set("")
        self.proxy_port_var.set("")
        
        # Set kill date to 10 days in the future
        future_date = datetime.date.today() + datetime.timedelta(days=10)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
        
        # Update UI state based on new values
        self.toggle_proxy_options()
        
        self.logger("Agent configuration reset to defaults")
        messagebox.showinfo("Reset", "Agent configuration has been reset to default values.")
    
    def set_30_days_expiry(self):
        """Set the kill date to 30 days from today"""
        future_date = datetime.date.today() + datetime.timedelta(days=30)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
    
    def validate_inputs(self):
        """Validate all input values"""
        # Validate beacon period (must be a positive integer)
        try:
            beacon_period = int(self.beacon_period_var.get())
            if beacon_period <= 0:
                messagebox.showerror("Validation Error", "Beacon period must be a positive integer.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Beacon period must be a valid integer.")
            return False
        
        # Validate jitter percentage (must be between 0 and 50)
        try:
            jitter = int(self.jitter_percentage_var.get())
            if jitter < 0 or jitter > 50:
                messagebox.showerror("Validation Error", "Jitter percentage must be between 0 and 50.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Jitter percentage must be a valid integer.")
            return False
        
        # Validate kill date (must be in dd/mm/yyyy format and in the future)
        try:
            kill_date = datetime.datetime.strptime(self.kill_date_var.get(), "%d/%m/%Y").date()
            today = datetime.date.today()
            if kill_date <= today:
                messagebox.showerror("Validation Error", "Kill date must be in the future.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Kill date must be in dd/mm/yyyy format.")
            return False
        
        # Validate max failures (must be a positive integer)
        try:
            max_failures = int(self.max_failures_var.get())
            if max_failures <= 0:
                messagebox.showerror("Validation Error", "Max failures must be a positive integer.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Max failures must be a valid integer.")
            return False
        
        # Validate max backoff time (must be a positive integer)
        try:
            max_backoff = int(self.max_backoff_var.get())
            if max_backoff <= 0:
                messagebox.showerror("Validation Error", "Max backoff time must be a positive integer.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Max backoff time must be a valid integer.")
            return False
            
        # Validate max sleep time (must be a positive integer)
        try:
            max_sleep = int(self.max_sleep_var.get())
            if max_sleep <= 0:
                messagebox.showerror("Validation Error", "Max sleep time must be a positive integer.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Max sleep time must be a valid integer.")
            return False
            
        # Validate User-Agent (must not be empty)
        if not self.user_agent_var.get().strip():
            messagebox.showerror("Validation Error", "User-Agent cannot be empty.")
            return False
            
        # Validate proxy settings if enabled
        if self.proxy_enabled_var.get():
            if self.proxy_type_var.get() != "system":
                # For manual proxy, validate server and port
                if not self.proxy_server_var.get().strip():
                    messagebox.showerror("Validation Error", "Proxy server cannot be empty when using manual proxy.")
                    return False
                
                try:
                    if self.proxy_port_var.get():
                        port = int(self.proxy_port_var.get())
                        if port <= 0 or port > 65535:
                            messagebox.showerror("Validation Error", "Proxy port must be between 1 and 65535.")
                            return False
                except ValueError:
                    messagebox.showerror("Validation Error", "Proxy port must be a valid integer.")
                    return False
        
        return True