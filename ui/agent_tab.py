import tkinter as tk
from tkinter import ttk, messagebox
import base64
import os
import sys
import json
from pathlib import Path
from utils.agent_generator import generate_pwsh_base64_str

class AgentGenerationTab:
    def __init__(self, parent, campaign_tab, logger):
        self.campaign_tab = campaign_tab  # to retrieve campaign settings
        self.logger = logger              # to log messages
        self.frame = ttk.Frame(parent)
        self.selected_agents = {}  # mapping agent name to tk.BooleanVar
        
        # Create the UI widgets
        self.create_widgets()

    def create_widgets(self):
        # Frame for checkboxes
        checkbox_frame = ttk.LabelFrame(self.frame, text="Select Agent Types")
        checkbox_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create checkbox for PowerShell Base64 agent option (simplified to only this option)
        agent_option = "Powershell Base64"
        var = tk.BooleanVar(value=True)
        chk = ttk.Checkbutton(checkbox_frame, text=agent_option, variable=var)
        chk.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.selected_agents[agent_option] = var

        # Button to generate agents
        self.btn_generate = ttk.Button(self.frame, text="Generate Agents", command=self.generate_agents_ui)
        self.btn_generate.pack(pady=5)
        
        # Text widget to display agent summary
        self.text_agent = tk.Text(self.frame, height=20)
        self.text_agent.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

    def generate_agents_ui(self):
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
        agents_folder = os.path.join(campaign_folder, "agents")
        if not os.path.exists(campaign_folder):
            messagebox.showerror("Error", f"Campaign folder '{campaign_folder}' does not exist. Start the campaign first.")
            return
        if not os.path.exists(agents_folder):
            os.makedirs(agents_folder, exist_ok=True)

        agent_results = []
        # For each selected agent type, generate the agent
        if self.selected_agents["Powershell Base64"].get():
            try:
                # Call the generate_pwsh_base64_str function directly from agent_generator.py
                result = generate_pwsh_base64_str(host, port, use_ssl, campaign_folder)
                agent_results.append(f"[-] Powershell Base64\n{result}")
            except Exception as e:
                error_msg = f"Error generating PowerShell Base64 agent: {e}"
                agent_results.append(f"[-] Powershell Base64 - Error: {str(e)}")
                self.logger(error_msg)
                # Print more detailed error for debugging
                import traceback
                self.logger(traceback.format_exc())

        if not agent_results:
            messagebox.showinfo("No Agents Selected", "Please select at least one agent type.")
            return

        self.text_agent.delete(1.0, tk.END)
        for p in agent_results:
            self.text_agent.insert(tk.END, p + "\n\n")
        self.logger("Agents generated in campaign folder.")