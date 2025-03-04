import os
import datetime
import logging

class LogManager:
    def __init__(self, log_area_widget=None):
        """Initialize the LogManager.
        
        Args:
            log_area_widget: The tkinter Text widget for displaying logs in the GUI
        """
        self.log_area_widget = log_area_widget
        self.log_file_path = None
        self.campaign_folder = None
        self.logs_folder = None
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        if log_area_widget:
            # Add handler to display logs in the GUI
            self.setup_gui_log_handler()
    
    def setup_gui_log_handler(self):
        """Set up a handler to display logs in the GUI text widget."""
        class TextHandler(logging.Handler):
            def __init__(self, text_widget, log_manager):
                logging.Handler.__init__(self)
                self.text_widget = text_widget
                self.log_manager = log_manager

            def emit(self, record):
                log_entry = self.format(record)
                self.log_manager.add_event_to_viewer(record.levelname, log_entry)
                log_entry += "\n"
                self.text_widget.config(state="normal")
                self.text_widget.insert("end", log_entry)
                self.text_widget.see("end")  # Scroll to the bottom
                self.text_widget.config(state="disabled")

        text_handler = TextHandler(self.log_area_widget, self)
        text_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(text_handler)
    
    def set_campaign_folder(self, campaign_name):
        """Set the campaign folder for logs.
        
        Args:
            campaign_name: Name of the campaign
        """
        self.campaign_folder = campaign_name + "_campaign"
        self.logs_folder = os.path.join(self.campaign_folder, "logs")
        os.makedirs(self.logs_folder, exist_ok=True)
        
        # Set up the main log file
        self.log_file_path = os.path.join(self.logs_folder, "event_log.txt")
        
        # Add a file handler to save logs to the file
        # First, remove any existing handlers to avoid duplicates when reloading a campaign
        for handler in self.logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                self.logger.removeHandler(handler)
        
        # Add the new file handler
        file_handler = logging.FileHandler(self.log_file_path)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)
        
        # Log campaign initialization
        is_existing = os.path.exists(self.log_file_path) and os.path.getsize(self.log_file_path) > 0
        if is_existing:
            self.log(f"Resuming existing campaign: {campaign_name}")
        else:
            self.log(f"Starting new campaign: {campaign_name}")
    
    def log(self, message):
        """Log a general message.
        
        Args:
            message: The message to log
        """
        self.logger.info(message)
    
    def add_event_to_viewer(self, event_type, details, client_id="N/A"):
        """Add an event to the event viewer and main log file.
        
        Args:
            event_type: Type of the event
            details: Details of the event
            client_id: ID of the client (default: "N/A")
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_event = f"[{timestamp}] [{client_id}] [{event_type}] {details}"
        
        if self.log_area_widget:
            self.log_area_widget.config(state="normal")
            self.log_area_widget.insert("end", formatted_event + "\n")
            self.log_area_widget.see("end")
            self.log_area_widget.config(state="disabled")
        
        if self.log_file_path:
            with open(self.log_file_path, "a") as log_file:
                log_file.write(formatted_event + "\n")
    
    def load_existing_logs(self, max_entries=100):
        """Load existing log entries from the campaign log file into the GUI.
        
        Args:
            max_entries: Maximum number of log entries to load (default: 100)
        """
        if not self.log_file_path or not os.path.exists(self.log_file_path):
            return
            
        try:
            with open(self.log_file_path, 'r') as f:
                # Read last N lines from the log file
                lines = f.readlines()
                last_lines = lines[-max_entries:] if len(lines) > max_entries else lines
                
                if self.log_area_widget:
                    self.log_area_widget.config(state="normal")
                    # Add a separator to indicate loaded logs
                    self.log_area_widget.insert("end", "--- Loading previous logs ---\n")
                    
                    # Add each log entry
                    for line in last_lines:
                        self.log_area_widget.insert("end", line)
                    
                    # Add another separator
                    self.log_area_widget.insert("end", "--- Current session logs ---\n")
                    self.log_area_widget.see("end")
                    self.log_area_widget.config(state="disabled")
        except Exception as e:
            self.logger.error(f"Error loading existing logs: {e}")
    
    def log_client_event(self, client_id, event_type, details):
        """Log an event for a specific client.
        
        Args:
            client_id: ID of the client
            event_type: Type of the event
            details: Details of the event
        """
        # Skip logging "Commands cleared" events to client logs
        if event_type == "Commands cleared" and "Pending commands cleared" in details:
            # Still log to main log but not client log
            self.log(f"[{client_id}] {event_type}: {details}")
            return
            
        # Log to the main logger
        self.log(f"[{client_id}] {event_type}: {details}")
        
        # Also log to the client-specific log file
        if self.logs_folder:
            client_log_file = os.path.join(self.logs_folder, f"{client_id}_log.txt")
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] [{event_type}] {details}\n"
            
            try:
                with open(client_log_file, "a") as f:
                    f.write(log_entry)
            except Exception as e:
                self.log(f"Error saving log in client {client_id} log file: {e}")
    
    def log_command_result(self, client_id, command_type, args, result):
        """Log a command result for a specific client.
        
        Args:
            client_id: ID of the client
            command_type: Type of the command
            args: Arguments of the command
            result: Result of the command
        """
        details = f"Command: {command_type} {args} | Result: {result}"
        self.log_client_event(client_id, "Command Result", details)