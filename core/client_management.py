import tkinter as tk
from tkinter import ttk
import datetime
import os
from core.cmd import CommandExecutor
from core.utils.client_identity import generate_client_id, extract_system_info
from core.utils.client_management_ui import ClientListUI, ClientDetailsUI


class ClientManager:
    def __init__(self, log_event):
        # key: client_id, value: dict with keys: last_seen, ip, hostname, pending_commands, history, system_info
        self.clients = {}
        self.command_update_callbacks = {}  # Dictionary to store callbacks
        self.log_event = log_event  # This is now the log_client_event method from LogManager
        self.client_verifier = None  # Will be set by the server to the ClientVerifier instance

    def add_client(self, ip, hostname="Unknown", username="Unknown", machine_guid="Unknown", 
                  os_version="Unknown", mac_address="Unknown", system_info=None):
        """Register a client with enhanced identification data"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate a unique client_id from system properties
        client_id = generate_client_id(ip, hostname, username, machine_guid, os_version)
        
        if system_info is None:
            system_info = {}
        
        if client_id not in self.clients:
            self.clients[client_id] = {
                "last_seen": now,
                "ip": ip,
                "hostname": hostname,
                "username": username,
                "machine_guid": machine_guid,
                "os_version": os_version,
                "mac_address": mac_address,
                "system_info": system_info,
                "pending_commands": [],
                "history": [],
                "verification_status": {
                    "verified": False,
                    "confidence": 0,
                    "warnings": ["New client"]
                }
            }
            self.log_event(client_id, "Client Connected", f"New client connected: {hostname}/{username}")
        else:
            # Update existing client information
            self.clients[client_id]["last_seen"] = now
            self.clients[client_id]["ip"] = ip
            self.clients[client_id]["hostname"] = hostname
            self.clients[client_id]["username"] = username
            self.clients[client_id]["mac_address"] = mac_address
            
            # Update any new system info properties while preserving existing ones
            if system_info:
                self.clients[client_id]["system_info"].update(system_info)
                
            self.log_event(client_id, "Client Updated", f"Client reconnected: {hostname}/{username}")
        
        return client_id

    def set_verification_status(self, client_id, verified, confidence, warnings):
        """Update the verification status of a client"""
        if client_id in self.clients:
            self.clients[client_id]["verification_status"] = {
                "verified": verified,
                "confidence": confidence,
                "warnings": warnings
            }

    def add_command(self, client_id, command_type, args, ip="Unknown", hostname="Unknown"):
        """Add a command to the client's pending commands"""
        # If we know the client already
        if client_id in self.clients:
            command = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": command_type,
                "args": args
            }
            self.clients[client_id]["pending_commands"].append(command)
            self.clients[client_id]["history"].append(command)
            self.log_event(client_id, "Command added", f"Command {command_type} with args {args} was added")
            
            # Notify listeners that a command has been added
            self.on_command_updated(client_id)
        else:
            # For backward compatibility, try to register client by IP if it's a valid client ID
            try:
                ip_address = ip if ip != "Unknown" else client_id
                self.add_client(ip_address, hostname)
                self.add_command(ip_address, command_type, args, ip, hostname)
            except Exception as e:
                self.log_event("ERROR", "Command Error", f"Failed to add command for unknown client {client_id}: {str(e)}")

    def add_command_result(self, client_id, timestamp, result):
        """Add a result to a command in the client's history"""
        if client_id in self.clients:
            # Find the command with the matching timestamp
            for command in self.clients[client_id]["history"]:
                if command.get("timestamp") == timestamp:
                    command["result"] = result
                    self.log_event(client_id, "Command Result", f"Result received for command at {timestamp}")
                    # Notify listeners that the command has been updated
                    self.on_command_updated(client_id)
                    return True
        return False

    def get_clients_info(self):
        """Get information about all clients"""
        return self.clients

    def get_client_history(self, client_id):
        """Get command history for a specific client"""
        return self.clients.get(client_id, {}).get("history", [])

    def get_pending_commands(self, client_id):
        """Get pending commands for a specific client"""
        return self.clients.get(client_id, {}).get("pending_commands", [])

    def clear_pending_commands(self, client_id):
        """Clear all pending commands for a client"""
        if client_id in self.clients:
            self.clients[client_id]["pending_commands"] = []
            self.log_event(client_id, "Commands cleared", f"Pending commands cleared")

    def register_command_update_callback(self, client_id, callback):
        """Registers a callback to be called when a command result is updated."""
        self.command_update_callbacks.setdefault(client_id, []).append(callback)

    def on_command_updated(self, client_id):
        """Calls all registered callbacks for the given client."""
        for callback in self.command_update_callbacks.get(client_id, []):
            callback()


class ClientManagementTab:
    def __init__(self, parent, client_manager, logger):
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager
        self.logger = logger
        self.executor = CommandExecutor(self.client_manager)
        
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