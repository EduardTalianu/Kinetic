import tkinter as tk
from tkinter import ttk
import logging
import core.client_management as client_management
import core.campaign_config as campaign_config
import core.agent_generation as agent_generation
import random
import string
import datetime
import os


class MainGUI:
    def __init__(self, master):
        self.log_file_path = None
        self.master = master
        master.title("Kinetic Compliance Matrix")

        # Configure logging
        self.configure_logging()

        # Create ClientManager instance
        self.client_manager = client_management.ClientManager(self.log_event)

        # Create Notebook
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Tabs
        self.create_tabs()

        # Add a Label above the log_text to act as a title for the area
        self.log_area_title_label = ttk.Label(self.master, text="Event Viewer")
        self.log_area_title_label.pack(fill=tk.X, padx=5, pady=(5, 0))  # Add some padding

        # Redirect logs to GUI Text widget (Moved below tabs)
        self.log_text = tk.Text(self.master, height=6)  # Reduced height here
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state="disabled")

        class TextHandler(logging.Handler):
            def __init__(self, text_widget, gui_instance):  # Add gui_instance
                logging.Handler.__init__(self)
                self.text_widget = text_widget
                self.gui_instance = gui_instance

            def emit(self, record):
                log_entry = self.format(record)
                self.gui_instance.add_event_to_viewer(record.levelname, log_entry)  # Call add_event_to_viewer from TextHandler
                log_entry += "\n"
                self.text_widget.config(state="normal")
                self.text_widget.insert(tk.END, log_entry)
                self.text_widget.see(tk.END)  # Scroll to the bottom
                self.text_widget.config(state="disabled")

        text_handler = TextHandler(self.log_text, self)  # Pass the instance
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
        self.client_management_tab = client_management.ClientManagementTab(self.notebook, self.client_manager, self.log)  # Client Management tab

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

        # save the log in the campaign folder
        campaign_name = self.campaign_tab.entry_campaign.get().strip()
        campaign_folder = campaign_name + "_campaign"
        
      # Create the logs folder inside the campaign folder if it doesn't exist
        logs_folder = os.path.join(campaign_folder, "logs")
        os.makedirs(logs_folder, exist_ok=True)

        self.log_file_path = os.path.join(logs_folder, "event_log.txt")

    # Custom logger
    def log(self, message):
        self.logger.info(message)

    def add_event_to_viewer(self, event_type, details, client_id="N/A"):
        """Adds an event to the log_text widget."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_event = f"[{timestamp}] [{client_id}] [{event_type}] {details}"
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, formatted_event + "\n")  # Add a newline
        self.log_text.see(tk.END)
        if self.log_file_path:
            with open(self.log_file_path, "a") as log_file:
                log_file.write(formatted_event + "\n")
        self.log_text.config(state="disabled")

    def log_event(self, client_id, event_type, details):
        """Logs an event to the main log and client's log."""
        self.log(f"[{client_id}] {event_type}: {details}")

        # Get the campaign name from the campaign tab
        campaign_name = self.campaign_tab.entry_campaign.get().strip()
        campaign_folder = campaign_name + "_campaign"
        logs_folder = os.path.join(campaign_folder, "logs")
        os.makedirs(logs_folder, exist_ok=True)  # Ensure logs folder exists
        
        client_log_file = os.path.join(logs_folder, f"{client_id}_log.txt")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format the log entry according to the requirements: timestamp, command, and result
        log_entry = f"[{timestamp}] [{event_type}] {details}\n"
        
        try:
            with open(client_log_file, "a") as f:
                f.write(log_entry)
        except Exception as e:
            self.log(f"Error saving log in client {client_id} log file: {e}")


def main():
    root = tk.Tk()
    gui = MainGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
