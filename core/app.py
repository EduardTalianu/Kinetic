import tkinter as tk
from tkinter import ttk
import logging
import os
import random
import string
import datetime
from core.logging import LogManager
from core.client import ClientManager
from ui.campaign_tab import CampaignConfigTab
from ui.agent_tab import AgentGenerationTab
from ui.client_tab import ClientManagementTab
from ui.certificate_tab import CertificateManagementTab
# Add import for the new Agent Configuration tab
from ui.agent_config_tab import AgentConfigTab

class MainGUI:
    def __init__(self, master):
        self.master = master
        master.title("Kinetic Compliance Matrix")
        
        # Set window size to make it more spacious
        master.geometry("1200x800")  # Making the window larger to accommodate the enhanced UI

        # Create the main GUI components in this order:
        # 1. Create notebook
        self.notebook = ttk.Notebook(master)
        
        # 2. Create log components
        self.log_area_title_label = ttk.Label(self.master, text="Event Viewer")
        self.log_text = tk.Text(self.master, height=6)  # Reduced height
        self.log_text.config(state="disabled")
        
        # 3. Initialize log manager
        self.log_manager = LogManager(self.log_text)
        
        # 4. Initialize client manager using log manager
        self.client_manager = ClientManager(self.log_manager.log_client_event)
        
        # 5. Create the tabs (which need the client manager and log manager)
        self.create_tabs()
        
        # 6. Pack UI elements in the right order (notebook first, then log components)
        self.notebook.pack(fill=tk.BOTH, expand=True)  # Expand to fill space
        self.log_area_title_label.pack(fill=tk.X, padx=5, pady=(5, 0))  # Add some padding
        self.log_text.pack(fill=tk.BOTH, expand=False)  # Not expanding to give more space to notebook
        
        # 7. Populate default campaign data
        self.populate_default_campaign_data()
        
        # 8. Set up notebook tab change event binding
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    def create_tabs(self):
        # Create and add tabs to the notebook, passing the necessary objects
        self.campaign_tab = CampaignConfigTab(self.notebook, self.client_manager, self.log_manager.log)
        self.agent_config_tab = AgentConfigTab(self.notebook, self.campaign_tab, self.log_manager.log)
        self.agent_generation_tab = AgentGenerationTab(self.notebook, self.campaign_tab, self.log_manager.log)
        self.client_management_tab = ClientManagementTab(self.notebook, self.client_manager, self.log_manager.log)
        self.certificate_tab = CertificateManagementTab(self.notebook, self.log_manager.log, self.campaign_tab)

        # Provide access to the log_manager to campaign_tab
        self.campaign_tab.log_manager = self.log_manager

        # Add tabs to notebook in desired order
        self.notebook.add(self.campaign_tab.frame, text="Campaign Config")
        self.notebook.add(self.agent_config_tab.frame, text="Agent Config")
        self.notebook.add(self.agent_generation_tab.frame, text="Agent Generation")
        self.notebook.add(self.client_management_tab.frame, text="Client Management")
        self.notebook.add(self.certificate_tab.frame, text="Certificate Management")
    
    def on_tab_changed(self, event):
        """Handle tab change events"""
        selected_tab = self.notebook.select()
        tab_id = self.notebook.index(selected_tab)
        
        # If switching to Agent Config tab, sync with campaign tab values
        if tab_id == 1:  # Agent Config tab (0-based index)
            self.agent_config_tab.sync_from_campaign_tab()
        
        # If switching to Agent Generation tab, apply agent config first
        elif tab_id == 2:  # Agent Generation tab
            # We don't force applying configurations here, just let the user know they should
            campaign_name = self.campaign_tab.entry_campaign.get().strip()
            if campaign_name:
                # Try to load any saved configuration
                self.agent_config_tab.load_configuration(campaign_name)

    def populate_default_campaign_data(self):
        """Populates the Campaign Config tab with default values."""
        # Generate a random campaign name
        campaign_name = "Campaign_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        # Default IP
        default_ip = "192.168.0.1"

        # Random port between 1024 and 65535
        random_port = random.randint(1024, 65535)

        # Set the values in the entry fields
        self.campaign_tab.entry_campaign.insert(0, campaign_name)
        self.campaign_tab.ip_var.set(default_ip)
        self.campaign_tab.entry_port.insert(0, str(random_port))
        
        # Set default values in agent config tab
        # Beacon period and kill date are now set in agent_config_tab, not campaign_tab
        
        # Set up the log manager with the campaign folder
        self.log_manager.set_campaign_folder(campaign_name)

    # Proxy methods for backward compatibility
    def log(self, message):
        """Proxy method to forward to log_manager.log."""
        self.log_manager.log(message)

    def log_event(self, client_id, event_type, details):
        """Proxy method to forward to log_manager.log_client_event."""
        self.log_manager.log_client_event(client_id, event_type, details)

    def add_event_to_viewer(self, event_type, details, client_id="N/A"):
        """Proxy method to forward to log_manager.add_event_to_viewer."""
        self.log_manager.add_event_to_viewer(event_type, details, client_id)


def main():
    root = tk.Tk()
    gui = MainGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()