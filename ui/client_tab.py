import tkinter as tk
from tkinter import ttk
from ui.client_list import ClientListUI
from ui.client_details import ClientDetailsUI
from core.cmd import CommandExecutor

class ClientManagementTab:
    def __init__(self, parent, client_manager, logger):
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager
        self.logger = logger
        
        # Initialize the CommandExecutor
        self.command_executor = CommandExecutor(self.client_manager)
        
        # Create the notebook for tabs
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Client List tab
        self.client_list_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.client_list_frame, text="Client List")
        
        # Initialize UI components
        self.client_list_ui = ClientListUI(
            self.client_list_frame, 
            self.client_manager, 
            self.logger, 
            self.open_client_details_tab
        )
        
        self.client_details_ui = ClientDetailsUI(
            self.notebook,
            self.client_manager,
            self.logger
        )
        
        # Initial refresh
        self.client_list_ui.refresh_client_list()

    def open_client_details_tab(self, client_id):
        """Opens a tab with detailed information about a client"""
        self.client_details_ui.create_client_details_tab(client_id)

    def refresh_client_list(self):
        """Refresh the client list"""
        self.client_list_ui.refresh_client_list()