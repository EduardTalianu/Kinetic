import tkinter as tk
from tkinter import ttk
import logging
import core.client_management as client_management
import core.campaign_config as campaign_config
import core.agent_generation as agent_generation
import core.log_management as log_management
import random
import string
import datetime
import os


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
        self.log_manager = log_management.LogManager(self.log_text)
        
        # 4. Initialize client manager using log manager
        self.client_manager = client_management.ClientManager(self.log_manager.log_client_event)
        
        # 5. Create the tabs (which need the client manager and log manager)
        self.create_tabs()
        
        # 6. Pack UI elements in the right order (notebook first, then log components)
        self.notebook.pack(fill=tk.BOTH, expand=True)  # Expand to fill space
        self.log_area_title_label.pack(fill=tk.X, padx=5, pady=(5, 0))  # Add some padding
        self.log_text.pack(fill=tk.BOTH, expand=False)  # Not expanding to give more space to notebook
        
        # 7. Populate default campaign data
        self.populate_default_campaign_data()

    def create_tabs(self):
        # Create and add tabs to the notebook, passing the necessary objects
        self.campaign_tab = campaign_config.CampaignConfigTab(self.notebook, self.client_manager, self.log_manager.log)
        self.agent_generation_tab = agent_generation.AgentGenerationTab(self.notebook, self.campaign_tab, self.log_manager.log)  # Agent Generation Tab
        self.client_management_tab = client_management.ClientManagementTab(self.notebook, self.client_manager, self.log_manager.log)  # Client Management tab

        self.notebook.add(self.campaign_tab.frame, text="Campaign Config")
        self.notebook.add(self.agent_generation_tab.frame, text="Agent Generation")  # Agent Generation is added second
        self.notebook.add(self.client_management_tab.frame, text="Client Management")  # Client management is added third.

    def populate_default_campaign_data(self):
        """Populates the Campaign Config tab with default values."""
        # Generate a random campaign name
        campaign_name = "Campaign_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        # Default IP
        default_ip = "192.168.0.1"

        # Random port between 1024 and 65535
        random_port = random.randint(1024, 65535)

        # Beacon period
        beacon_period = "5"

        # Kill date 10 days in the future
        future_date = datetime.date.today() + datetime.timedelta(days=10)
        kill_date = future_date.strftime("%d/%m/%Y")

        # Set the values in the entry fields
        self.campaign_tab.entry_campaign.insert(0, campaign_name)
        self.campaign_tab.ip_var.set(default_ip)
        self.campaign_tab.entry_port.insert(0, str(random_port))
        self.campaign_tab.entry_beacon.insert(0, beacon_period)
        self.campaign_tab.entry_kill_date.insert(0, kill_date)

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