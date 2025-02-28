import tkinter as tk
from tkinter import ttk
import logging
import core.client_management as client_management
import core.campaign_config as campaign_config
import core.agent_generation as agent_generation
import random
import string
import datetime


class MainGUI:
    def __init__(self, master):
        self.master = master
        master.title("Kinetic Compliance Matrix")

        # Configure logging
        self.configure_logging()

        # Create ClientManager instance
        self.client_manager = client_management.ClientManager()

        # Create Notebook
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Tabs
        self.create_tabs()

        # Redirect logs to GUI Text widget (Moved below tabs)
        self.log_text = tk.Text(self.master, height=6)  # Reduced height here
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state="disabled")

        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                logging.Handler.__init__(self)
                self.text_widget = text_widget

            def emit(self, record):
                log_entry = self.format(record) + "\n"
                self.text_widget.config(state="normal")
                self.text_widget.insert(tk.END, log_entry)
                self.text_widget.see(tk.END)  # Scroll to the bottom
                self.text_widget.config(state="disabled")

        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(text_handler)
        
        # Populate the default data for the campaign
        self.populate_default_campaign_data()

    def configure_logging(self):
        # Configure logging for the entire application
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def create_tabs(self):
        # Create and add tabs to the notebook, passing the necessary objects
        self.campaign_tab = campaign_config.CampaignConfigTab(self.notebook, self.client_manager, self.log)
        self.agent_generation_tab = agent_generation.AgentGenerationTab(self.notebook, self.campaign_tab, self.log)  # Agent Generation Tab
        self.client_management_tab = client_management.ClientManagementTab(self.notebook, self.client_manager) #Client Management tab

        self.notebook.add(self.campaign_tab.frame, text="Campaign Config")
        self.notebook.add(self.agent_generation_tab.frame, text="Agent Generation") # Agent Generation is added second
        self.notebook.add(self.client_management_tab.frame, text="Client Management") # Client management is added third.
        
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

    # Custom logger
    def log(self, message):
        self.logger.info(message)


def main():
    root = tk.Tk()
    gui = MainGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
