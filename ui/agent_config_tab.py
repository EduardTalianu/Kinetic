import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import datetime
from typing import Dict, Any, List, Optional

# Import plugin manager
from plugins.plugin_manager import get_plugin_manager

class AgentConfigTab:
    def __init__(self, parent, campaign_tab, logger):
        self.frame = ttk.Frame(parent)
        self.campaign_tab = campaign_tab  # Reference to campaign tab to access/update campaign settings
        self.logger = logger
        
        # Initialize plugin manager
        self.plugin_manager = get_plugin_manager()
        self.plugin_manager.discover_plugins()
        
        # Get available agent types
        self.agent_types = self.plugin_manager.get_plugin_names()
        if not self.agent_types:
            self.agent_types = ["PowerShell"]  # Fallback if no plugins found
        
        # Initialize agent type variable
        self.agent_type_var = tk.StringVar(value=self.agent_types[0] if self.agent_types else "PowerShell")
        
        # Dictionary to store all config widgets by agent type
        self.config_frames = {}
        self.config_widgets = {}
        
        # Initialize legacy variables for backward compatibility
        self._init_legacy_vars()
        
        # Create the UI components
        self.create_widgets()
        
        # Create initial config widgets for default agent type
        self.create_config_widgets(self.agent_type_var.get())
    
    def _init_legacy_vars(self):
        """Initialize legacy variables for backward compatibility"""
        # These variables are used by other components and should be maintained
        self.beacon_period_var = tk.StringVar(value="5")
        self.kill_date_var = tk.StringVar()
        self.jitter_percentage_var = tk.StringVar(value="20")
        self.user_agent_var = tk.StringVar(value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
        self.random_sleep_enabled_var = tk.BooleanVar(value=False)
        self.max_sleep_var = tk.StringVar(value="10")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.proxy_enabled_var = tk.BooleanVar(value=False)
        self.proxy_type_var = tk.StringVar(value="system")
        self.proxy_server_var = tk.StringVar()
        self.proxy_port_var = tk.StringVar()
        
        # Set the default kill date (10 days in the future)
        future_date = datetime.date.today() + datetime.timedelta(days=10)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
        
        # Additional variables
        self.max_failures_var = tk.StringVar(value="3")
        self.max_backoff_var = tk.StringVar(value="10")
    
    def create_widgets(self):
        """Create the UI components for agent configuration"""
        # Main container
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
        
        # Agent type selection frame
        agent_type_frame = ttk.LabelFrame(main_frame, text="Agent Type")
        agent_type_frame.pack(fill=tk.X, pady=10)
        
        # Use pack instead of grid for the agent selection
        type_label_frame = ttk.Frame(agent_type_frame)
        type_label_frame.pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Label(type_label_frame, text="Agent Type:").pack(side=tk.LEFT)
        
        type_combo_frame = ttk.Frame(agent_type_frame)
        type_combo_frame.pack(side=tk.LEFT, padx=5, pady=5)
        self.agent_type_combo = ttk.Combobox(
            type_combo_frame, 
            textvariable=self.agent_type_var,
            values=self.agent_types,
            state="readonly",
            width=20
        )
        self.agent_type_combo.pack(side=tk.LEFT)
        
        # Agent description label
        self.agent_description = ttk.Label(agent_type_frame, text="", wraplength=500)
        self.agent_description.pack(pady=5, padx=5, anchor=tk.W)
        
        # Bind agent type selection to update config widgets
        self.agent_type_combo.bind("<<ComboboxSelected>>", self.on_agent_type_changed)
        
        # Update the description initially
        self.update_agent_description()
        
        # Create a frame to hold agent-specific config widgets
        self.config_container = ttk.Frame(main_frame)
        self.config_container.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Kill date section - common to all agent types
        kill_date_frame = ttk.LabelFrame(main_frame, text="Campaign Settings")
        kill_date_frame.pack(fill=tk.X, pady=10)
        
        # Use pack instead of grid for the kill date section
        kill_date_row = ttk.Frame(kill_date_frame)
        kill_date_row.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(kill_date_row, text="Kill Date:").pack(side=tk.LEFT, padx=5)
        self.kill_date_entry = ttk.Entry(kill_date_row, textvariable=self.kill_date_var, width=15)
        self.kill_date_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(kill_date_row, text="Date when agent will stop functioning (dd/mm/yyyy)").pack(side=tk.LEFT, padx=5)
        
        # Generate a date 30 days from now button
        ttk.Button(kill_date_row, text="+ 30 Days", command=self.set_30_days_expiry).pack(side=tk.LEFT, padx=5)
        
        # Buttons for saving and applying configuration
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=15)
        
        ttk.Button(button_frame, text="Save Configuration", command=self.save_configuration).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_to_defaults).pack(side=tk.LEFT, padx=5)
        
        # Create scrollable area for config options (useful for plugins with many options)
        self.create_scrollable_container()
    
    def create_scrollable_container(self):
        """Create a scrollable container for config options"""
        # Clear existing content in config container
        for widget in self.config_container.winfo_children():
            widget.destroy()
        
        # Create canvas and scrollbar
        self.canvas = tk.Canvas(self.config_container, borderwidth=0)
        self.scrollbar = ttk.Scrollbar(self.config_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        # Configure canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack elements
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel to scroll
        self.canvas.bind_all("<MouseWheel>", self.on_mousewheel)
    
    def on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def update_agent_description(self):
        """Update the agent description text based on selected agent type"""
        agent_type = self.agent_type_var.get()
        plugin = self.plugin_manager.get_plugin(agent_type)
        
        if plugin:
            # Get description and capabilities
            description = plugin.get_description()
            capabilities = plugin.get_agent_capabilities()
            
            # Format capabilities as a comma-separated list
            capabilities_str = ", ".join(capability.replace("_", " ").title() for capability in capabilities)
            
            # Update the description label
            self.agent_description.config(
                text=f"{description}\n\nCapabilities: {capabilities_str}"
            )
        else:
            self.agent_description.config(
                text="Selected agent type not available."
            )
    
    def on_agent_type_changed(self, event=None):
        """Handler for agent type selection"""
        self.update_agent_description()
        self.create_config_widgets(self.agent_type_var.get())
    
    def create_config_widgets(self, agent_type):
        """Create configuration widgets based on agent type"""
        # Check if we already have widgets for this agent type
        if agent_type in self.config_frames:
            # Show the existing frame and hide others
            for a_type, frame in self.config_frames.items():
                if a_type == agent_type:
                    frame.pack(fill=tk.BOTH, expand=True)
                else:
                    frame.pack_forget()
            return
        
        # Get the plugin
        plugin = self.plugin_manager.get_plugin(agent_type)
        if not plugin:
            return
        
        # Create a new frame for this agent type
        agent_frame = ttk.Frame(self.scrollable_frame)
        self.config_frames[agent_type] = agent_frame
        
        # Get plugin options
        options = plugin.get_options()
        
        # Create widgets for each option
        self.config_widgets[agent_type] = {}
        
        # Group options by category
        option_groups = {}
        for option_name, option_info in options.items():
            group_name = self._get_option_group(option_name)
            if group_name not in option_groups:
                option_groups[group_name] = []
            option_groups[group_name].append((option_name, option_info))
        
        # Create widgets for each group
        for group_name, group_options in option_groups.items():
            if group_name:
                # Create a group frame
                group_frame = ttk.LabelFrame(agent_frame, text=group_name.capitalize())
                group_frame.pack(fill=tk.X, pady=5)
                parent_frame = group_frame
            else:
                # Use agent frame directly for ungrouped options
                parent_frame = agent_frame
            
            # Process each option in the group
            for option_name, option_info in group_options:
                option_type = option_info.get("type", "string")
                option_default = option_info.get("default", "")
                option_desc = option_info.get("description", "")
                option_required = option_info.get("required", False)
                option_values = option_info.get("values", [])
                
                # Create a row frame for this option
                option_row = ttk.Frame(parent_frame)
                option_row.pack(fill=tk.X, padx=5, pady=2)
                
                # Add option label
                label = ttk.Label(option_row, text=f"{option_name.replace('_', ' ').title()}:", width=20, anchor=tk.W)
                label.pack(side=tk.LEFT, padx=5)
                
                # Create widget based on option type
                if option_type == "bool":
                    # Boolean toggle - use checkbox
                    var = tk.BooleanVar(value=option_default)
                    
                    # Special case for syncing with legacy variables
                    if option_name == "random_sleep_enabled":
                        var = self.random_sleep_enabled_var
                    elif option_name == "proxy_enabled":
                        var = self.proxy_enabled_var
                    
                    widget = ttk.Checkbutton(option_row, variable=var)
                    
                    # Add command for toggling dependent options
                    if option_name == "random_sleep_enabled":
                        widget.config(command=self.toggle_sleep_options)
                    elif option_name == "proxy_enabled":
                        widget.config(command=self.toggle_proxy_options)
                    
                    widget.pack(side=tk.LEFT)
                    
                elif option_type == "list" and option_values:
                    # List selection - use combobox
                    var = tk.StringVar(value=option_default)
                    
                    # Special case for syncing with legacy variables
                    if option_name == "proxy_type":
                        var = self.proxy_type_var
                    elif option_name == "jitter_percentage":
                        var = self.jitter_percentage_var
                    
                    widget = ttk.Combobox(option_row, textvariable=var, values=option_values, width=20, state="readonly")
                    widget.pack(side=tk.LEFT)
                    
                    # Add bind for proxy type changes
                    if option_name == "proxy_type":
                        widget.bind("<<ComboboxSelected>>", self.on_proxy_type_changed)
                    
                else:
                    # String or int - use entry field
                    var = tk.StringVar(value=str(option_default))
                    
                    # Special case for syncing with legacy variables
                    if option_name == "beacon_period":
                        var = self.beacon_period_var
                    elif option_name == "max_sleep_time":
                        var = self.max_sleep_var
                    elif option_name == "user_agent":
                        var = self.user_agent_var
                    elif option_name == "username":
                        var = self.username_var
                    elif option_name == "password":
                        var = self.password_var
                    elif option_name == "proxy_server":
                        var = self.proxy_server_var
                    elif option_name == "proxy_port":
                        var = self.proxy_port_var
                    elif option_name == "max_failures":
                        var = self.max_failures_var
                    elif option_name == "max_backoff_time":
                        var = self.max_backoff_var
                    
                    # Adjust width based on expected string length
                    width = 20
                    if option_name == "user_agent":
                        width = 60
                    elif option_name in ["beacon_period", "max_sleep_time", "max_failures", "max_backoff_time"]:
                        width = 5
                    
                    widget = ttk.Entry(option_row, textvariable=var, width=width)
                    
                    # Special case for password field
                    if option_name == "password":
                        widget.config(show="*")
                    
                    widget.pack(side=tk.LEFT, padx=5)
                    
                    # Special case for max_sleep_time - may start disabled
                    if option_name == "max_sleep_time":
                        if not self.random_sleep_enabled_var.get():
                            widget.config(state="disabled")
                    
                    # Special case for proxy settings - may start disabled
                    if option_name in ["proxy_server", "proxy_port"]:
                        if not self.proxy_enabled_var.get() or (option_name in ["proxy_server", "proxy_port"] and self.proxy_type_var.get() == "system"):
                            widget.config(state="disabled")
                
                # Store the widget and variable
                self.config_widgets[agent_type][option_name] = {
                    "widget": widget,
                    "var": var,
                    "type": option_type
                }
                
                # Add description
                desc_label = ttk.Label(option_row, text=option_desc, wraplength=300)
                desc_label.pack(side=tk.LEFT, padx=20, fill=tk.X, expand=True)
        
        # Add this frame to the container
        agent_frame.pack(fill=tk.BOTH, expand=True)
        
        # Hide other frames
        for a_type, frame in self.config_frames.items():
            if a_type != agent_type:
                frame.pack_forget()
    
    def _get_option_group(self, option_name):
        """Get the option group name based on option name prefixes"""
        if option_name in ["beacon_period", "jitter_percentage"]:
            return "beacon"
        elif option_name in ["random_sleep_enabled", "max_sleep_time"]:
            return "sleep"
        elif option_name in ["max_failures", "max_backoff_time"]:
            return "fallback"
        elif option_name in ["proxy_enabled", "proxy_type", "proxy_server", "proxy_port"]:
            return "proxy"
        elif option_name in ["username", "password"]:
            return "authentication"
        else:
            return None
    
    def toggle_sleep_options(self):
        """Enable or disable sleep configuration options based on checkbox"""
        state = "normal" if self.random_sleep_enabled_var.get() else "disabled"
        
        # Update widget in current agent's config
        agent_type = self.agent_type_var.get()
        if agent_type in self.config_widgets and "max_sleep_time" in self.config_widgets[agent_type]:
            self.config_widgets[agent_type]["max_sleep_time"]["widget"].config(state=state)
        
        # Legacy support
        if hasattr(self, 'max_sleep_entry'):
            self.max_sleep_entry.config(state=state)
    
    def on_proxy_type_changed(self, event=None):
        """Update fields when proxy type changes"""
        manual_proxy_state = "normal" if self.proxy_type_var.get() != "system" else "disabled"
        
        # Update widgets in current agent's config
        agent_type = self.agent_type_var.get()
        if agent_type in self.config_widgets:
            if "proxy_server" in self.config_widgets[agent_type]:
                self.config_widgets[agent_type]["proxy_server"]["widget"].config(state=manual_proxy_state)
            if "proxy_port" in self.config_widgets[agent_type]:
                self.config_widgets[agent_type]["proxy_port"]["widget"].config(state=manual_proxy_state)
                
        # Legacy support
        if hasattr(self, 'proxy_server_entry'):
            self.proxy_server_entry.config(state=manual_proxy_state)
        if hasattr(self, 'proxy_port_entry'):
            self.proxy_port_entry.config(state=manual_proxy_state)
    
    def toggle_proxy_options(self):
        """Enable or disable proxy configuration options based on checkbox"""
        state = "normal" if self.proxy_enabled_var.get() else "disabled"
        
        # Update widgets in current agent's config
        agent_type = self.agent_type_var.get()
        if agent_type in self.config_widgets:
            if "proxy_type" in self.config_widgets[agent_type]:
                self.config_widgets[agent_type]["proxy_type"]["widget"].config(state=state)
            
            # Only enable server and port if not system proxy and proxy is enabled
            manual_proxy_state = "normal" if (self.proxy_enabled_var.get() and self.proxy_type_var.get() != "system") else "disabled"
            
            if "proxy_server" in self.config_widgets[agent_type]:
                self.config_widgets[agent_type]["proxy_server"]["widget"].config(state=manual_proxy_state)
            if "proxy_port" in self.config_widgets[agent_type]:
                self.config_widgets[agent_type]["proxy_port"]["widget"].config(state=manual_proxy_state)
        
        # Legacy support
        if hasattr(self, 'proxy_type_combo'):
            self.proxy_type_combo.config(state=state)
        if hasattr(self, 'proxy_server_entry'):
            self.proxy_server_entry.config(state=manual_proxy_state)
        if hasattr(self, 'proxy_port_entry'):
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
        
        # Get the current agent type
        agent_type = self.agent_type_var.get()
        
        # Create configuration dictionary
        config = {
            "agent_type": agent_type,
            "kill_date": self.kill_date_var.get(),
            "last_modified": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Add agent-specific options
        if agent_type in self.config_widgets:
            for option_name, option_data in self.config_widgets[agent_type].items():
                # Skip group frames
                if option_name.startswith("group_"):
                    continue
                    
                var = option_data.get("var")
                if var:
                    # Convert to appropriate type
                    value = var.get()
                    
                    if option_data.get("type") == "bool":
                        value = bool(var.get())
                    elif option_data.get("type") == "int":
                        try:
                            value = int(value)
                        except ValueError:
                            pass
                    
                    config[option_name] = value
        
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
                
            # Set agent type if available
            if "agent_type" in config and config["agent_type"] in self.agent_types:
                self.agent_type_var.set(config["agent_type"])
                self.on_agent_type_changed()  # Update UI for this agent type
                
            # Set kill date
            if "kill_date" in config:
                self.kill_date_var.set(config["kill_date"])
                
            # Get current agent type from config
            agent_type = config.get("agent_type", self.agent_type_var.get())
            
            # Set option values for this agent type
            if agent_type in self.config_widgets:
                for option_name, option_value in config.items():
                    if option_name in self.config_widgets[agent_type]:
                        var = self.config_widgets[agent_type][option_name].get("var")
                        if var:
                            # For boolean variables
                            if isinstance(var, tk.BooleanVar):
                                var.set(bool(option_value))
                            else:
                                var.set(str(option_value))
            
            # Update UI state based on loaded values
            self.toggle_sleep_options()
            self.toggle_proxy_options()
                
            self.logger(f"Loaded agent configuration from {config_file}")
            return True
        except Exception as e:
            self.logger(f"Error loading agent configuration: {e}")
            return False
    
    def reset_to_defaults(self):
        """Reset all values to defaults"""
        # Get current agent type
        agent_type = self.agent_type_var.get()
        
        # Get the plugin
        plugin = self.plugin_manager.get_plugin(agent_type)
        if not plugin:
            return
            
        # Get default configuration
        defaults = plugin.get_default_config()
        
        # Reset all values to defaults
        if agent_type in self.config_widgets:
            for option_name, option_data in self.config_widgets[agent_type].items():
                # Skip group frames
                if option_name.startswith("group_"):
                    continue
                    
                if option_name in defaults:
                    var = option_data.get("var")
                    if var:
                        if isinstance(var, tk.BooleanVar):
                            var.set(bool(defaults[option_name]))
                        else:
                            var.set(str(defaults[option_name]))
        
        # Set kill date to 10 days in the future
        future_date = datetime.date.today() + datetime.timedelta(days=10)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
        
        # Update UI state based on new values
        self.toggle_sleep_options()
        self.toggle_proxy_options()
        
        self.logger("Agent configuration reset to defaults")
        messagebox.showinfo("Reset", "Agent configuration has been reset to default values.")
    
    def set_30_days_expiry(self):
        """Set the kill date to 30 days from today"""
        future_date = datetime.date.today() + datetime.timedelta(days=30)
        self.kill_date_var.set(future_date.strftime("%d/%m/%Y"))
    
    def validate_inputs(self):
        """Validate all input values"""
        # Get the current agent type
        agent_type = self.agent_type_var.get()
        
        # Get the plugin
        plugin = self.plugin_manager.get_plugin(agent_type)
        if not plugin:
            messagebox.showerror("Validation Error", f"Agent plugin '{agent_type}' not found.")
            return False
            
        # Collect current configuration
        config = {}
        
        if agent_type in self.config_widgets:
            for option_name, option_data in self.config_widgets[agent_type].items():
                # Skip group frames
                if option_name.startswith("group_"):
                    continue
                    
                var = option_data.get("var")
                if var:
                    if option_data.get("type") == "bool":
                        config[option_name] = bool(var.get())
                    elif option_data.get("type") == "int":
                        try:
                            config[option_name] = int(var.get())
                        except ValueError:
                            config[option_name] = var.get()
                    else:
                        config[option_name] = var.get()
        
        # Validate kill date
        try:
            kill_date = datetime.datetime.strptime(self.kill_date_var.get(), "%d/%m/%Y").date()
            today = datetime.date.today()
            if kill_date <= today:
                messagebox.showerror("Validation Error", "Kill date must be in the future.")
                return False
        except ValueError:
            messagebox.showerror("Validation Error", "Kill date must be in dd/mm/yyyy format.")
            return False
        
        # Use plugin's validation method
        errors = plugin.validate_config(config)
        if errors:
            error_msg = "\n".join([f"{key}: {', '.join(msgs)}" for key, msgs in errors.items()])
            messagebox.showerror("Validation Error", f"Configuration validation failed:\n{error_msg}")
            return False
        
        return True