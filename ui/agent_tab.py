import tkinter as tk
from tkinter import ttk, messagebox
import base64
import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# Import plugin manager
from plugins.plugin_manager import get_plugin_manager
from utils.agent_generator import generate_pwsh_base64_str

class AgentGenerationTab:
    def __init__(self, parent, campaign_tab, logger):
        self.campaign_tab = campaign_tab  # to retrieve campaign settings
        self.logger = logger              # to log messages
        self.frame = ttk.Frame(parent)
        self.selected_agent_type = tk.StringVar(value="PowerShell")
        
        # Initialize plugin manager
        self.plugin_manager = get_plugin_manager()
        self.plugin_manager.discover_plugins()
        
        # Create the UI widgets
        self.create_widgets()

    def create_widgets(self):
        # Main container with better spacing
        main_frame = ttk.Frame(self.frame, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Agent selection section
        agent_type_frame = ttk.LabelFrame(main_frame, text="Select Agent Type")
        agent_type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Get available agent plugins
        agent_types = self.plugin_manager.get_plugin_names()
        if not agent_types:
            agent_types = ["PowerShell"]  # Fallback if no plugins found
        
        # Agent type selection
        ttk.Label(agent_type_frame, text="Agent Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.agent_type_combo = ttk.Combobox(
            agent_type_frame, 
            textvariable=self.selected_agent_type,
            values=agent_types,
            state="readonly",
            width=20
        )
        self.agent_type_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.agent_type_combo.bind("<<ComboboxSelected>>", self.on_agent_type_changed)
        
        # Agent description
        self.agent_description = ttk.Label(agent_type_frame, text="", wraplength=400)
        self.agent_description.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # Update the description initially
        self.update_agent_description()
        
        # Output format section
        output_frame = ttk.LabelFrame(main_frame, text="Output Format")
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create output format options based on agent capabilities
        self.output_format_var = tk.StringVar(value="base64")
        
        ttk.Radiobutton(
            output_frame, 
            text="Raw Agent Code", 
            variable=self.output_format_var, 
            value="ps1"
        ).grid(row=0, column=0, sticky=tk.W, padx=15, pady=2)
        
        ttk.Radiobutton(
            output_frame, 
            text="Base64 Encoded", 
            variable=self.output_format_var, 
            value="base64"
        ).grid(row=0, column=1, sticky=tk.W, padx=15, pady=2)
        
        ttk.Radiobutton(
            output_frame, 
            text="PowerShell Command", 
            variable=self.output_format_var, 
            value="encoded_command"
        ).grid(row=0, column=2, sticky=tk.W, padx=15, pady=2)
        
        # Generation button and agent options
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Generate button
        self.btn_generate = ttk.Button(options_frame, text="Generate Agent", command=self.generate_agents_ui)
        self.btn_generate.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Text widget to display agent summary
        self.text_agent = tk.Text(main_frame, height=20)
        self.text_agent.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.text_agent, orient="vertical", command=self.text_agent.yview)
        self.text_agent.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def on_agent_type_changed(self, event=None):
        """Handler for agent type selection"""
        self.update_agent_description()
        
        # Adjust output format options based on agent capabilities
        agent_type = self.selected_agent_type.get()
        plugin = self.plugin_manager.get_plugin(agent_type)
        
        # We could check plugin capabilities here and enable/disable format options
        # depending on what the plugin supports
        # For now, we'll keep it simple

    def update_agent_description(self):
        """Update the agent description text based on selected agent type"""
        agent_type = self.selected_agent_type.get()
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

    def generate_agents_ui(self):
        """Generate agents based on selected agent type and configuration"""
        # Get campaign settings
        host = self.campaign_tab.get_ip()
        port = self.campaign_tab.get_port()
        use_ssl = self.campaign_tab.get_ssl()
        
        try:
            campaign_name = self.campaign_tab.entry_campaign.get().strip()
        except AttributeError:
            messagebox.showerror("Error", "Please create a campaign first.")
            return

        if not host or not port or not campaign_name:
            messagebox.showerror("Error", "Please fill in Campaign Config with valid Campaign Name, C&C IP, and Port first.")
            return

        campaign_folder = campaign_name + "_campaign"
        if not os.path.exists(campaign_folder):
            messagebox.showerror("Error", f"Campaign folder '{campaign_folder}' does not exist. Start the campaign first.")
            return
            
        # Get the selected agent type and format
        agent_type = self.selected_agent_type.get()
        output_format = self.output_format_var.get()
        
        # Load agent configuration
        agent_config = self.load_agent_config(campaign_folder)
        
        # Set the output format
        agent_config["format"] = output_format
        
        try:
            # Clear the text widget before displaying new content
            self.text_agent.delete(1.0, tk.END)
            
            # For now, use the existing function for backwards compatibility
            if agent_type == "PowerShell" and output_format == "base64":
                result = generate_pwsh_base64_str(host, port, use_ssl, campaign_folder)
                
                # Check if result is a dictionary (new format) or string (old format)
                if isinstance(result, dict):
                    # Display the summary
                    self.text_agent.insert(tk.END, f"Agent Generation Summary\n\n")
                    
                    if "summary" in result:
                        self.text_agent.insert(tk.END, f"{result['summary']}\n\n")
                    
                    # Display instructions if available
                    if "instructions" in result:
                        self.text_agent.insert(tk.END, "Instructions:\n")
                        self.text_agent.insert(tk.END, f"{result['instructions']}\n\n")
                    
                    # Display the generated code
                    if "code" in result:
                        self.text_agent.insert(tk.END, "Agent Code:\n")
                        self.text_agent.insert(tk.END, f"{result['code']}\n\n")
                    
                    # Display generated files if any
                    if "files" in result and result["files"]:
                        self.text_agent.insert(tk.END, "Generated Files:\n")
                        for file_path in result["files"]:
                            self.text_agent.insert(tk.END, f"- {file_path}\n")
                else:
                    # Old format (just a string)
                    self.text_agent.insert(tk.END, result)
                    
                self.logger("PowerShell Base64 agent generated successfully.")
                return
                
            # Get the plugin
            plugin = self.plugin_manager.get_plugin(agent_type)
            if not plugin:
                messagebox.showerror("Error", f"Agent plugin '{agent_type}' not found.")
                return
                
            # Set up server address with SSL
            http = "https" if use_ssl else "http"
            server_address = f"{host}:{port}"
            
            # Load path rotation configuration
            rotation_info = self.load_rotation_info(campaign_folder)
            
            # Prepare campaign settings
            campaign_settings = {
                "server_address": server_address,
                "rotation_info": rotation_info,
                "campaign_folder": campaign_folder,
                "ssl_enabled": use_ssl,
                "http_protocol": http
            }
            
            # Generate the agent
            result = plugin.generate(agent_config, campaign_settings)
            
            # Display the result
            self.text_agent.delete(1.0, tk.END)
            
            # Show summary
            if isinstance(result, dict):
                self.text_agent.insert(tk.END, f"Agent Generation Summary\n\n")
                
                if "summary" in result:
                    self.text_agent.insert(tk.END, f"{result['summary']}\n\n")
                
                # Show instructions
                if "instructions" in result:
                    self.text_agent.insert(tk.END, "Instructions:\n")
                    self.text_agent.insert(tk.END, f"{result['instructions']}\n\n")
                
                # Show code
                if "code" in result:
                    self.text_agent.insert(tk.END, "Agent Code:\n")
                    self.text_agent.insert(tk.END, f"{result['code']}\n\n")
                
                # Show generated files
                if "files" in result and result["files"]:
                    self.text_agent.insert(tk.END, "Generated Files:\n")
                    for file_path in result["files"]:
                        self.text_agent.insert(tk.END, f"- {file_path}\n")
            else:
                # Handle old-style result (string)
                self.text_agent.insert(tk.END, result)
                
            self.logger(f"{agent_type} agent generated successfully.")
            
        except Exception as e:
            error_msg = f"Error generating {agent_type} agent: {e}"
            self.logger(error_msg)
            messagebox.showerror("Error", error_msg)
            
            # Print more detailed error for debugging
            import traceback
            self.logger(traceback.format_exc())

    def load_agent_config(self, campaign_folder):
        """Load agent configuration from the campaign folder"""
        agent_config = {}
        
        # Try to load agent configuration
        agent_config_file = os.path.join(campaign_folder, "agent_config.json")
        if os.path.exists(agent_config_file):
            try:
                with open(agent_config_file, 'r') as f:
                    agent_config = json.load(f)
                self.logger(f"Loaded agent configuration from {agent_config_file}")
            except Exception as e:
                self.logger(f"Error loading agent configuration: {e}")
                # We'll continue with an empty config
        
        return agent_config

    def load_rotation_info(self, campaign_folder):
        """Load path rotation information from the campaign folder"""
        rotation_info = {
            "current_rotation_id": 0,
            "next_rotation_time": int(time.time()) + 3600,
            "rotation_interval": 3600,
            "current_paths": {"path_pool": []}
        }
        
        # Try to load path rotation state
        path_rotation_file = os.path.join(campaign_folder, "path_rotation_state.json")
        if os.path.exists(path_rotation_file):
            try:
                with open(path_rotation_file, 'r') as f:
                    rotation_state = json.load(f)
                    rotation_info["current_rotation_id"] = rotation_state.get("rotation_counter", 0)
                    rotation_info["next_rotation_time"] = rotation_state.get("next_rotation_time", rotation_info["next_rotation_time"])
                    rotation_info["rotation_interval"] = rotation_state.get("rotation_interval", rotation_info["rotation_interval"])
                    
                    # Get path pool if available
                    path_pool = rotation_state.get("current_paths", {}).get("path_pool", [])
                    rotation_info["current_paths"]["path_pool"] = path_pool
                    
                self.logger(f"Loaded path rotation state from {path_rotation_file}")
            except Exception as e:
                self.logger(f"Error loading path rotation state: {e}")
        
        return rotation_info