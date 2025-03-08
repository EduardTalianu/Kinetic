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
        self.beacon_period_var = tk.StringVar(value="5")  # Default value
        self.kill_date_var = tk.StringVar()
        self.jitter_percentage_var = tk.StringVar(value="20")  # Default jitter is 20%
        
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
            "when generating new agents. Note that some advanced parameters are hardcoded in "
            "the agent and cannot be modified without changing the agent code."
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
        
        # Failback & Recovery Settings
        ttk.Label(fallback_frame, text="Max Failures Before Fallback:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_failures_var = tk.StringVar(value="3")  # Default to 3
        self.max_failures_entry = ttk.Entry(fallback_frame, textvariable=self.max_failures_var, width=5)
        self.max_failures_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(fallback_frame, text="Number of failed connections before using fallback paths").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fallback_frame, text="Max Backoff Time (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_backoff_var = tk.StringVar(value="300")  # Default to 5 minutes
        self.max_backoff_entry = ttk.Entry(fallback_frame, textvariable=self.max_backoff_var, width=5)
        self.max_backoff_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(fallback_frame, text="Maximum time between reconnection attempts").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)

         # Auto ID Rotation Settings
        auto_rotation_frame = ttk.LabelFrame(main_frame, text="Automatic Client ID Rotation")
        auto_rotation_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(auto_rotation_frame, text="Enable Auto ID Rotation:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.auto_rotation_var = tk.BooleanVar(value=True)
        self.auto_rotation_check = ttk.Checkbutton(auto_rotation_frame, variable=self.auto_rotation_var)
        self.auto_rotation_check.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(auto_rotation_frame, text="Automatically rotate client ID for better security").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(auto_rotation_frame, text="Rotation Frequency:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.rotation_frequency_var = tk.StringVar(value="17")
        self.rotation_frequency_entry = ttk.Entry(auto_rotation_frame, textvariable=self.rotation_frequency_var, width=5)
        self.rotation_frequency_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(auto_rotation_frame, text="Number of communications before rotating client ID").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)

        
        # Non-editable configuration information
        info_frame = ttk.LabelFrame(main_frame, text="Hardcoded Agent Settings (Non-Editable)")
        info_frame.pack(fill=tk.X, pady=10)
        
        self.info_text = tk.Text(info_frame, height=8, wrap=tk.WORD, state=tk.NORMAL)
        self.info_text.pack(fill=tk.X, padx=5, pady=5)
        self.info_text.insert(tk.END, 
            "The following settings are hardcoded in the agent and cannot be modified without changing the agent generation code:\n\n"
            "• TLS Version: 1.2\n"
            "• User-Agent String: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36\n"
            "• Encryption: AES-256-CBC with PKCS7 padding\n"
            "• Communication Paths: Set in Campaign Config tab\n"
            "• Path Rotation: Set in Campaign Config tab\n"
        )
        self.info_text.config(state=tk.DISABLED)
        
        # Buttons for saving and applying configuration
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=15)
        
        ttk.Button(button_frame, text="Save Configuration", command=self.save_configuration).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_to_defaults).pack(side=tk.LEFT, padx=5)
    
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
            "auto_rotation_enabled": self.auto_rotation_var.get(),
            "rotation_frequency": self.rotation_frequency_var.get(),
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
                
            # Load new auto rotation settings
            if "auto_rotation_enabled" in config:
                self.auto_rotation_var.set(config["auto_rotation_enabled"])
                
            if "rotation_frequency" in config:
                self.rotation_frequency_var.set(config["rotation_frequency"])
            
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
        self.auto_rotation_var.set(True)
        self.rotation_frequency_var.set("17")
        
        # Set kill date to 10 days in the future
        future_date = datetime.date.today() + datetime.timedelta(days=10)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
        
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
        
        try:
            rotation_frequency = int(self.rotation_frequency_var.get())
            if rotation_frequency <= 0:
                messagebox.showerror("Validation Error", "Rotation frequency must be a positive integer.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Rotation frequency must be a valid integer.")
            return False
        
        return True
        
  