import tkinter as tk
from tkinter import ttk, messagebox
import base64
import os
import sys
import importlib.util
from pathlib import Path

# -------------------------------
# Helper functions to load agent generators
# -------------------------------

def load_agent_module(module_name):
    """Dynamically load agent generator modules from the core/helpers directory."""
    helpers_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core", "helpers")
    module_path = os.path.join(helpers_dir, f"{module_name}.py")
    
    if not os.path.exists(module_path):
        raise ImportError(f"Agent module {module_name} not found at {module_path}")
    
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# -------------------------------
# AgentGenerationTab class
# -------------------------------

class AgentGenerationTab:
    def __init__(self, parent, campaign_tab, logger):
        self.campaign_tab = campaign_tab  # to retrieve campaign settings
        self.logger = logger              # to log messages
        self.frame = ttk.Frame(parent)
        self.selected_agents = {}  # mapping agent name to tk.BooleanVar
        
        # Initialize the agent modules
        self.init_agent_modules()
        
        # Create the UI widgets
        self.create_widgets()

    def init_agent_modules(self):
        """Initialize the agent generator modules."""
        # Map agent names to their module and function - Simplified to only PowerShell Base64
        self.agent_options = {
            "Powershell Base64": ("powershell_agents", "generate_pwsh_base64_str")
        }
        
        # Load the modules
        self.modules = {}
        for agent_name, (module_name, _) in self.agent_options.items():
            if module_name not in self.modules:
                try:
                    self.modules[module_name] = load_agent_module(module_name)
                except ImportError as e:
                    self.logger(f"Failed to load module {module_name}: {str(e)}")
                    # Create empty core/helpers directory if it doesn't exist
                    helpers_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core", "helpers")
                    os.makedirs(helpers_dir, exist_ok=True)

    def create_widgets(self):
        # Frame for checkboxes
        checkbox_frame = ttk.LabelFrame(self.frame, text="Select Agent Types")
        checkbox_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create checkboxes for each agent option
        for i, option in enumerate(self.agent_options):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(checkbox_frame, text=option, variable=var)
            chk.grid(row=i // 2, column=i % 2, sticky=tk.W, padx=5, pady=2)
            self.selected_agents[option] = var

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
        # For each selected agent type, generate the agent and save it in the campaign folder.
        for option, (module_name, func_name) in self.agent_options.items():
            if self.selected_agents[option].get():
                try:
                    # Get the module
                    module = self.modules.get(module_name)
                    if not module:
                        raise ImportError(f"Module {module_name} not loaded")
                    
                    # Get the function
                    func = getattr(module, func_name)
                    if not func:
                        raise AttributeError(f"Function {func_name} not found in module {module_name}")
                    
                    # Call the function
                    agent_text = func(host, port, use_ssl, campaign_folder)
                    agent_results.append(f"[-] {option}\n{agent_text}")
                except Exception as e:
                    agent_results.append(f"[-] {option} - Error: {e}")
                    self.logger(f"Error generating agent {option}: {e}")

        if not agent_results:
            messagebox.showinfo("No Agents Selected", "Please select at least one agent type.")
            return

        self.text_agent.delete(1.0, tk.END)
        for p in agent_results:
            self.text_agent.insert(tk.END, p + "\n\n")
        self.logger("Agents generated in campaign folder.")