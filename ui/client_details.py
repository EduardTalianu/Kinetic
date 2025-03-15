import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
from ui.client_interaction import ClientInteractionUI
from ui.client_files import ClientFilesUI

class ClientDetailsUI:
    """Handles the UI components for displaying client details"""
    
    def __init__(self, notebook, client_manager, logger):
        """
        Initialize the client details UI handler
        
        Args:
            notebook: The parent notebook widget
            client_manager: The client manager instance
            logger: Function for logging events
        """
        self.notebook = notebook
        self.client_manager = client_manager
        self.logger = logger
        self.client_details_tabs = {}  # Keep track of client details tabs
        self.result_text = None  # Will be set when a tab is created
    
    def create_client_details_tab(self, client_id):
        """
        Create a tab showing detailed information about a client
        
        Args:
            client_id: The unique identifier for the client
        """
        # Check if the tab already exists
        if client_id in self.client_details_tabs:
            self.notebook.select(self.client_details_tabs[client_id]["frame"])
            return

        details_frame = ttk.Frame(self.notebook)
        
        # Add close button to tab
        tab_text = f"Client {client_id}"
        self.notebook.add(details_frame, text=tab_text)
        
        # Create a close button for the tab
        close_button_frame = ttk.Frame(details_frame)
        close_button_frame.pack(fill=tk.X, pady=(5, 0), padx=5, anchor="ne")
        close_button = ttk.Button(
            close_button_frame, 
            text="Close Tab", 
            command=lambda: self.close_client_tab(client_id)
        )
        close_button.pack(side=tk.RIGHT)
        
        self.notebook.select(details_frame)  # Open the new tab

        client_info = self.client_manager.get_clients_info().get(client_id, {})
        
        # Create a notebook for the client details to organize information
        client_notebook = ttk.Notebook(details_frame)
        client_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab for system information
        sys_info_frame = ttk.Frame(client_notebook)
        client_notebook.add(sys_info_frame, text="System Information")
        
        # Tab for command history
        history_frame = ttk.Frame(client_notebook)
        client_notebook.add(history_frame, text="Command History")

        # Tab for verification information
        verification_frame = ttk.Frame(client_notebook)
        client_notebook.add(verification_frame, text="Verification")
        
        # Tab for interaction
        interaction_frame = ttk.Frame(client_notebook)
        client_notebook.add(interaction_frame, text="Interaction")
        
        # Tab for file management (NEW)
        files_frame = ttk.Frame(client_notebook)
        client_notebook.add(files_frame, text="Files")
        
        # System Information Tab
        self.populate_system_info_tab(sys_info_frame, client_info)
        
        # Verification Tab
        self.populate_verification_tab(verification_frame, client_info)
        
        # Command History Tab - Treeview for Command History
        columns = ("Timestamp", "Type", "Arguments", "Result")
        history_tree = ttk.Treeview(history_frame, columns=columns, show="headings")
        history_tree.heading("Timestamp", text="Timestamp")
        history_tree.heading("Type", text="Type")
        history_tree.heading("Arguments", text="Arguments")
        history_tree.heading("Result", text="Result Status")

        # Adjust column widths
        history_tree.column("Timestamp", width=150)
        history_tree.column("Type", width=100)
        history_tree.column("Arguments", width=200)
        history_tree.column("Result", width=100)

        history_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar for history tree
        history_scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=history_tree.yview)
        history_tree.configure(yscrollcommand=history_scrollbar.set)
        history_scrollbar.pack(side="right", fill="y")

        # Create a scrolled text widget for displaying detailed result
        result_frame = ttk.LabelFrame(history_frame, text="Command Result Details")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bind a function to handle selection change
        history_tree.bind("<ButtonRelease-1>", lambda event, tree=history_tree: self.on_select_command(event, tree, client_id))
        history_tree.bind("<Return>", lambda event, tree=history_tree: self.on_select_command(event, tree, client_id))

        self.populate_history_tree(client_id, history_tree)
        
        # Initialize the interaction tab
        self.client_interaction = ClientInteractionUI(interaction_frame, client_id, self.client_manager, self.logger)
        
        # Initialize the files tab (NEW)
        self.client_files = ClientFilesUI(files_frame, client_id, self.client_manager, self.logger)

        # Store history_tree and frame for later access
        self.client_details_tabs[client_id] = {
            "frame": details_frame, 
            "tree": history_tree,
            "notebook": client_notebook,
            "interaction": self.client_interaction,
            "files": self.client_files,  # NEW
            "verification_frame": verification_frame  # Store reference to verification frame
        }
        
        # Bind the tab selection event to refresh the verification tab
        client_notebook.bind("<<NotebookTabChanged>>", lambda e: self.on_client_tab_changed(e, client_id, client_notebook))
        
        # Register the callback to update the history tree
        self.client_manager.register_command_update_callback(client_id,
                                                            lambda: self.update_client_history_tree(client_id))

    def on_client_tab_changed(self, event, client_id, notebook):
        """Handle tab changes in the client notebook"""
        current_tab = notebook.select()
        tab_text = notebook.tab(current_tab, "text")
        
        # If the Verification tab is selected, refresh it
        if tab_text == "Verification" and client_id in self.client_details_tabs:
            verification_frame = self.client_details_tabs[client_id].get("verification_frame")
            if verification_frame:
                updated_client_info = self.client_manager.get_clients_info().get(client_id, {})
                if updated_client_info:
                    self.populate_verification_tab(verification_frame, updated_client_info)
    
    def close_client_tab(self, client_id):
        """Close the client details tab"""
        if client_id in self.client_details_tabs:
            tab_frame = self.client_details_tabs[client_id]["frame"]
            tab_index = self.notebook.index(tab_frame)
            self.notebook.forget(tab_index)
            del self.client_details_tabs[client_id]

    def populate_system_info_tab(self, parent_frame, client_info):
        """Populate the system information tab with client details with nice formatting for the new ID format"""
        # Create scrollable canvas for system info
        canvas = tk.Canvas(parent_frame, width=600)
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=canvas.yview)
        
        scroll_frame = ttk.Frame(canvas)
        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Basic client information section
        basic_frame = ttk.LabelFrame(scroll_frame, text="Basic Information")
        basic_frame.pack(fill=tk.X, padx=10, pady=5, anchor="n")
        
        # Extract and format the client ID
        client_id = client_info.get("client_id", "Unknown")
        
        # Check if client ID has the new format (e.g. "ABCDE-img.jpeg")
        if "-img.jpeg" in client_id:
            # Split the ID to highlight the random part separately
            id_parts = client_id.split("-")
            if len(id_parts) > 0:
                random_part = id_parts[0]
                formatted_id = f"{random_part} (Agent {client_id})"
            else:
                formatted_id = client_id
        else:
            formatted_id = client_id
        
        # Two-column layout for basic info with increased width
        labels = [
            ("Agent ID:", formatted_id),
            ("IP Address:", client_info.get("ip", "Unknown")),
            ("Hostname:", client_info.get("hostname", "Unknown")),
            ("Last Seen:", client_info.get("last_seen", "Unknown"))
        ]
        
        for i, (label, value) in enumerate(labels):
            ttk.Label(basic_frame, text=label, width=15, anchor="e").grid(row=i//2, column=i%2*2, sticky="e", padx=5, pady=2)
            value_text = ttk.Label(basic_frame, text=value, width=32, anchor="w")
            value_text.grid(row=i//2, column=i%2*2+1, sticky="w", padx=5, pady=2)
            
        # Advanced system information section if available
        if "system_info" in client_info and client_info["system_info"]:
            advanced_frame = ttk.LabelFrame(scroll_frame, text="Advanced System Information")
            advanced_frame.pack(fill=tk.X, padx=10, pady=5, anchor="n")
            
            row = 0
            for key, value in client_info["system_info"].items():
                # Skip ClientId key since we already display it formatted
                if key.lower() != 'clientid':
                    ttk.Label(advanced_frame, text=f"{key}:", width=15, anchor="e").grid(row=row, column=0, sticky="e", padx=5, pady=2)
                    
                    # Handle different value types
                    if isinstance(value, dict):
                        value_str = json.dumps(value, indent=2)
                    elif isinstance(value, list):
                        value_str = ", ".join(str(item) for item in value)
                    else:
                        value_str = str(value)
                    
                    value_text = ttk.Label(advanced_frame, text=value_str, wraplength=400, anchor="w")
                    value_text.grid(row=row, column=1, sticky="w", padx=5, pady=2)
                    row += 1

    def force_campaign_key(self):
        """Force the client to use the campaign key instead of a client-specific key"""
        client_id = self.client_id
        
        # Try to get server from client manager
        server = None
        if hasattr(self.client_manager, 'server'):
            server = self.client_manager.server
        
        # Check if server has encryption service
        encryption_service = None
        if server and hasattr(server, 'encryption_service'):
            encryption_service = server.encryption_service
        
        # Use encryption service if available
        if encryption_service:
            encryption_service.remove_client_key(client_id)
            self.logger(f"Forced use of campaign key for client {client_id} via encryption service")
            return True
        
        # Fall back to client manager if it has remove_client_key method
        if hasattr(self.client_manager, 'remove_client_key'):
            self.client_manager.remove_client_key(client_id)
            self.logger(f"Forced use of campaign key for client {client_id} via client manager")
            return True
        
        # Legacy fallback - remove directly from client_keys if exists
        if hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys:
            del self.client_manager.client_keys[client_id]
            
            # Also remove key rotation timestamp if it exists
            if client_id in self.client_manager.clients and 'key_rotation_time' in self.client_manager.clients[client_id]:
                del self.client_manager.clients[client_id]['key_rotation_time']
            
            self.logger(f"Forced use of campaign key for client {client_id} via direct removal")
            return True
        
        self.logger(f"Failed to force campaign key for client {client_id} - no suitable method found")
        return False

    def populate_verification_tab(self, parent_frame, client_info):
        """Populate the verification tab with identity verification information and key status"""
        # Clear existing widgets first if any
        for widget in parent_frame.winfo_children():
            widget.destroy()
        
        # Get latest client info directly from client_manager
        client_id = client_info.get("client_id")
        
        # This is a critical part - if client_id isn't found in the expected location
        # try to find it from other sources
        if not client_id:
            # Look in the client info more thoroughly
            if isinstance(client_info, dict):
                # Try to get from the object keys if it's a client from clients collection
                for key in self.client_manager.get_clients_info().keys():
                    if key in client_info or client_info.get('ip') == self.client_manager.get_clients_info()[key].get('ip'):
                        client_id = key
                        break
        
        # Final fallback - try to find client ID based on matching hostnames or IPs if we have them
        if not client_id and 'hostname' in client_info and 'ip' in client_info:
            for cid, ci in self.client_manager.get_clients_info().items():
                if (ci.get('hostname') == client_info.get('hostname') and 
                    ci.get('ip') == client_info.get('ip')):
                    client_id = cid
                    break
        
        if client_id:
            # Log that we've identified the client ID
            print(f"Verification tab working with client ID: {client_id}")
            
            # Get fresh data from client_manager
            updated_client_info = self.client_manager.get_clients_info().get(client_id, {})
            if updated_client_info:
                client_info = updated_client_info
                # Make sure client_id is stored in the updated info
                client_info["client_id"] = client_id
        else:
            print("Warning: Could not determine client ID in verification tab")
        
        verification_status = client_info.get("verification_status", {
            "verified": False,
            "confidence": 0,
            "warnings": ["New client"]
        })
        
        # Verification status indicator
        status_frame = ttk.Frame(parent_frame)
        status_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Verification confidence progress bar
        ttk.Label(status_frame, text="Identity Confidence:").pack(side=tk.LEFT, padx=5)
        confidence = verification_status.get("confidence", 0)
        progress = ttk.Progressbar(status_frame, length=200, maximum=100, value=confidence)
        progress.pack(side=tk.LEFT, padx=5)
        ttk.Label(status_frame, text=f"{confidence:.1f}%").pack(side=tk.LEFT, padx=5)
        
        # Verification status
        verified = verification_status.get("verified", False)
        status_text = "✓ Verified" if verified else "❌ Unverified"
        status_color = "#008000" if verified else "#FF0000" 
        status_label = ttk.Label(status_frame, text=status_text, foreground=status_color, font=("Arial", 10, "bold"))
        status_label.pack(side=tk.LEFT, padx=20)
        
        # Manual refresh button
        refresh_button = ttk.Button(
            status_frame, 
            text="Refresh Status", 
            command=lambda: self.refresh_verification_tab(parent_frame, {"client_id": client_id})
        )
        refresh_button.pack(side=tk.RIGHT, padx=10)
        
        # ---- Key Status Section ----
        key_frame = ttk.LabelFrame(parent_frame, text="Encryption Key Status")
        key_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Determine key status using multiple methods
        has_unique_key = False
        
        # Try to get encryption service
        server = None
        encryption_service = None
        
        if hasattr(self.client_manager, 'server'):
            server = self.client_manager.server
        
        if server and hasattr(server, 'encryption_service'):
            encryption_service = server.encryption_service
            if encryption_service:
                has_unique_key = encryption_service.has_client_key(client_id)
        
        # Fallback options if encryption service not available
        if not encryption_service:
            # Check using has_unique_key method on client manager
            if hasattr(self.client_manager, 'has_unique_key'):
                has_unique_key = self.client_manager.has_unique_key(client_id)
            # Direct check of client_keys attribute
            elif hasattr(self.client_manager, 'client_keys') and client_id:
                has_unique_key = client_id in self.client_manager.client_keys
            
            # Additional check in client info
            if not has_unique_key and client_id in self.client_manager.clients and 'key_rotation_time' in self.client_manager.clients[client_id]:
                has_unique_key = True
        
        # Key type indicator
        key_type_frame = ttk.Frame(key_frame)
        key_type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(key_type_frame, text="Key Type:").pack(side=tk.LEFT, padx=5)
        
        key_type = "Client-Specific Key" if has_unique_key else "Campaign Default Key"
        key_type_color = "#008000" if has_unique_key else "#FF8C00"  # Green if client-specific, orange if default
        self.key_type_label = ttk.Label(key_type_frame, text=key_type, foreground=key_type_color, font=("Arial", 10, "bold"))
        self.key_type_label.pack(side=tk.LEFT, padx=5)
        
        # Key status details
        key_details_frame = ttk.Frame(key_frame)
        key_details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add rotation timestamp if available
        if 'key_rotation_time' in client_info:
            ttk.Label(key_details_frame, text=f"Last Key Rotation: {client_info['key_rotation_time']}").pack(anchor="w", padx=5, pady=2)
            has_unique_key = True  # If we have rotation time, we definitely have a unique key
        elif has_unique_key:
            ttk.Label(key_details_frame, text="Key has been rotated (timestamp not available)").pack(anchor="w", padx=5, pady=2)
        else:
            ttk.Label(key_details_frame, text="No key rotation has occurred").pack(anchor="w", padx=5, pady=2)
        
        # Key action buttons frame
        key_action_frame = ttk.Frame(key_frame)
        key_action_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # Key rotation button
        def request_key_rotation():
            nonlocal client_id  # Use the client_id from the outer scope
            
            # Extra debug to see what client ID we're using
            print(f"Requesting key rotation for client: {client_id}")
            
            if not client_id:
                tk.messagebox.showerror("Key Rotation Error", "Cannot identify client ID for key rotation")
                return
                    
            if verified:
                # Add a key rotation command to the client
                try:
                    self.client_manager.add_command(client_id, "key_rotation", "Initiate key rotation")
                    tk.messagebox.showinfo("Key Rotation", f"Key rotation request sent to client {client_id}")
                    # Refresh the tab after sending the command
                    self.refresh_verification_tab(parent_frame, {"client_id": client_id})
                except Exception as e:
                    tk.messagebox.showerror("Key Rotation Error", f"Could not request key rotation: {str(e)}")
            else:
                tk.messagebox.showwarning("Key Rotation", "Client must be verified before key rotation can occur")
        
        rotation_button = ttk.Button(
            key_action_frame, 
            text="Request Key Rotation", 
            command=request_key_rotation,
            state="normal" if verified else "disabled"
        )
        rotation_button.pack(side=tk.LEFT, padx=5)
        
        # Force Session Key button - now uses the new implementation
        def force_session_key():
            nonlocal client_id, has_unique_key
            
            if not client_id:
                tk.messagebox.showerror("Key Management Error", "Cannot identify client ID")
                return
            
            try:
                # Use the new centralized method
                success = self.force_campaign_key()
                
                if success:
                    # Update UI
                    has_unique_key = False
                    self.key_type_label.config(text="Campaign Default Key", foreground="#FF8C00")
                    
                    tk.messagebox.showinfo("Key Management", 
                        f"Forced use of campaign default key for client {client_id}.\n"
                        f"The system will now use the campaign-wide key for this client.")
                    
                    # Log the change
                    self.logger(f"Forced use of campaign default key for client {client_id}")
                    
                    # Refresh the tab
                    self.refresh_verification_tab(parent_frame, {"client_id": client_id})
                else:
                    tk.messagebox.showerror("Key Management Error", 
                        "Could not force campaign key. This may be due to missing encryption service.")
                
            except Exception as e:
                tk.messagebox.showerror("Key Management Error", f"Failed to force session key: {str(e)}")
        
        # Add Force Session Key button
        force_key_button = ttk.Button(
            key_action_frame, 
            text="Force Campaign Key", 
            command=force_session_key,
            state="normal" if has_unique_key else "disabled"
        )
        force_key_button.pack(side=tk.LEFT, padx=5)
        
        # Add a note about key rotation
        ttk.Label(
            key_action_frame, 
            text="Note: Key rotation requires client verification",
            font=("Arial", 8, "italic"),
            foreground="#666666"
        ).pack(side=tk.LEFT, padx=5)
        
        # Warnings section
        warnings_frame = ttk.LabelFrame(parent_frame, text="Verification Warnings")
        warnings_frame.pack(fill=tk.X, padx=10, pady=10)
        
        warnings = verification_status.get("warnings", [])
        if warnings:
            for warning in warnings:
                ttk.Label(warnings_frame, text=f"• {warning}", foreground="#FF4500").pack(anchor="w", padx=10, pady=2)
        else:
            ttk.Label(warnings_frame, text="No verification warnings", foreground="#008000").pack(anchor="w", padx=10, pady=2)
        
        # Explanation section
        explanation_frame = ttk.LabelFrame(parent_frame, text="About Verification & Key Rotation")
        explanation_frame.pack(fill=tk.X, padx=10, pady=10)
        
        explanation_text = """
        Client verification uses multiple system identifiers to verify that a client is who they claim to be. 
        The confidence score is calculated based on the stability of identifiers like:
        
        • Machine GUID (most important)
        • MAC address
        • Hostname and username
        • OS version and hardware information
        
        A confidence score above 70% is considered verified. Warning signs include changes to critical identifiers.
        
        Key rotation enhances security by using a unique encryption key for each verified client. This prevents
        a compromise of one client from affecting others. Only verified clients can receive unique keys.
        """
        
        explanation_label = ttk.Label(explanation_frame, text=explanation_text, wraplength=400, justify=tk.LEFT)
        explanation_label.pack(padx=10, pady=10)

    def refresh_verification_tab(self, parent_frame, client_info):
        """Force refresh of the verification tab"""
        client_id = client_info.get("client_id")
        
        # If we don't have a client_id, try to determine it
        if not client_id:
            # First check if this client info is actually a client ID itself
            if isinstance(client_info, str) and client_info in self.client_manager.get_clients_info():
                client_id = client_info
            # Otherwise look through client info for identifying info
            elif isinstance(client_info, dict):
                # Try the IP and hostname combo if available
                if 'hostname' in client_info and 'ip' in client_info:
                    for cid, ci in self.client_manager.get_clients_info().items():
                        if (ci.get('hostname') == client_info.get('hostname') and 
                            ci.get('ip') == client_info.get('ip')):
                            client_id = cid
                            break
        
        if client_id:
            # Get fresh data
            updated_client_info = self.client_manager.get_clients_info().get(client_id, {})
            if updated_client_info:
                # Add client_id to info for future reference
                updated_client_info["client_id"] = client_id
                self.populate_verification_tab(parent_frame, updated_client_info)
                tk.messagebox.showinfo("Refresh", "Verification status updated")
            else:
                tk.messagebox.showwarning("Refresh", f"Client {client_id} not found")
        else:
            tk.messagebox.showerror("Refresh", "Cannot identify client ID for refresh")

    def populate_history_tree(self, client_id, history_tree):
        """Populates the history tree with the client's command history."""
        history_tree.delete(*history_tree.get_children())  # Clear the tree
        history = self.client_manager.get_client_history(client_id)
        for command in history:
            result_status = "Pending" if "result" not in command else "Completed"
            history_tree.insert("", tk.END, values=(
                command.get("timestamp", "Unknown"),
                command.get("command_type", "Unknown"),
                command.get("args", ""),
                result_status
            ))

    def update_client_history_tree(self, client_id):
        """Updates the client's history tree."""
        if client_id in self.client_details_tabs:
            history_tree = self.client_details_tabs[client_id]["tree"]
            self.populate_history_tree(client_id, history_tree)

    def on_select_command(self, event, tree, client_id):
        """Displays the details of the selected command in the ScrolledText widget."""
        selected_item = tree.selection()
        if selected_item:
            item_values = tree.item(selected_item, 'values')
            if len(item_values) >= 1:
                # Extract timestamp and find the detailed result from the client history
                timestamp = item_values[0]
                client_history = self.client_manager.get_client_history(client_id)
                for command in client_history:
                    if command.get('timestamp') == timestamp:
                        result = command.get('result', 'No result available')
                        # Display result in the ScrolledText widget
                        self.result_text.config(state=tk.NORMAL)
                        self.result_text.delete("1.0", tk.END)
                        self.result_text.insert(tk.END, result)
                        self.result_text.config(state=tk.DISABLED)
                        break