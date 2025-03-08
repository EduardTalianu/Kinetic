import tkinter as tk
from tkinter import ttk, messagebox

class ClientListUI:
    """Handles the UI components for displaying the client list"""
    
    def __init__(self, parent_frame, client_manager, logger, on_client_select):
        """
        Initialize the client list UI handler
        
        Args:
            parent_frame: The parent frame widget
            client_manager: Client manager for tracking clients
            logger: Function for logging events
            on_client_select: Callback function when a client is selected for details view
        """
        self.parent_frame = parent_frame
        self.client_manager = client_manager
        self.logger = logger
        self.on_client_select = on_client_select
        self.auto_refresh_job = None
        self.create_widgets()
    
    def create_widgets(self):
        """Create the widgets for the client list UI"""
        # Treeview for active clients with enhanced columns including original and current IDs
        columns = ("Original Client ID", "Current Client ID", "IP", "Hostname", "Username", "OS Version", "Verification", "Last Seen", "Pending Commands")
        self.tree = ttk.Treeview(self.parent_frame, columns=columns, show="headings")
        self.tree.heading("Original Client ID", text="Original Client ID")
        self.tree.heading("Current Client ID", text="Current Client ID")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("Username", text="Username")
        self.tree.heading("OS Version", text="OS Version")
        self.tree.heading("Verification", text="Verification")
        self.tree.heading("Last Seen", text="Last Seen")
        self.tree.heading("Pending Commands", text="Pending Commands")

        # Adjust column widths
        self.tree.column("Original Client ID", width=150)
        self.tree.column("Current Client ID", width=150)
        self.tree.column("IP", width=120)
        self.tree.column("Hostname", width=120)
        self.tree.column("Username", width=120)
        self.tree.column("OS Version", width=150)
        self.tree.column("Verification", width=100)
        self.tree.column("Last Seen", width=150)
        self.tree.column("Pending Commands", width=100)

        self.tree.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(self.parent_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Enhanced context menu with client ID rotation option
        self.context_menu = tk.Menu(self.parent_frame, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.open_client_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Rotate Client ID", command=self.request_client_id_rotation)
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", lambda e: self.open_client_details())

        # Refresh button and auto-refresh option
        refresh_frame = ttk.Frame(self.parent_frame)
        refresh_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.btn_refresh = ttk.Button(refresh_frame, text="Refresh", command=self.refresh_client_list)
        self.btn_refresh.pack(side=tk.LEFT, padx=5)
        
        self.auto_refresh_var = tk.BooleanVar(value=True)  # Default to enabled
        self.auto_refresh_cb = ttk.Checkbutton(
            refresh_frame, 
            text="Auto Refresh (3s)", 
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        )
        self.auto_refresh_cb.pack(side=tk.LEFT, padx=5)
        
        # Start auto-refresh since it's enabled by default
        self.schedule_auto_refresh()
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh on/off based on checkbox state"""
        if self.auto_refresh_var.get():
            self.schedule_auto_refresh()
        else:
            if self.auto_refresh_job:
                self.parent_frame.after_cancel(self.auto_refresh_job)
                self.auto_refresh_job = None

    def schedule_auto_refresh(self):
        """Schedule the next auto-refresh"""
        self.refresh_client_list()
        if self.auto_refresh_var.get():
            self.auto_refresh_job = self.parent_frame.after(3000, self.schedule_auto_refresh)  # 3 seconds

    def refresh_client_list(self):
        """Refresh the client list display with improved ID chain tracking"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # First: build a map of all true original IDs and their chains
        original_to_current = {}  # Maps original_id -> current_id
        
        # Find all true original IDs (the start of each chain)
        for client_id, info in self.client_manager.get_clients_info().items():
            # Get the true original ID for this client
            true_original = self.client_manager.get_true_original_id(client_id)
            
            if true_original:
                # If this is a true original ID
                if true_original == client_id:
                    # This is a true original ID, get its current ID
                    current_id = info.get("current_client_id", client_id)
                    original_to_current[true_original] = current_id
                elif true_original in original_to_current:
                    # This is part of a chain we're already tracking
                    # Check if this client is more current than what we have
                    if info.get("current_client_id"):
                        # Update the current ID for this chain if needed
                        original_to_current[true_original] = info.get("current_client_id")
        
        # Second: display each original client with its most current ID
        for original_id, current_id in original_to_current.items():
            # Get the original client info
            original_info = self.client_manager.get_clients_info().get(original_id, {})
            
            # Get the current client info, if different
            current_info = original_info
            if current_id != original_id and current_id in self.client_manager.get_clients_info():
                current_info = self.client_manager.get_clients_info()[current_id]
            
            # Use the most up-to-date fields from either original or current
            hostname = current_info.get("hostname", "Unknown")
            if hostname == "Unknown" and "system_info" in current_info:
                hostname = current_info["system_info"].get("Hostname", "Unknown")
                
            username = current_info.get("username", "Unknown")
            if username == "Unknown" and "system_info" in current_info:
                username = current_info["system_info"].get("Username", "Unknown")
                
            os_version = current_info.get("os_version", "Unknown")
            if os_version == "Unknown" and "system_info" in current_info:
                os_version = current_info["system_info"].get("OsVersion", "Unknown")
            
            # Get verification status (prefer from original client)
            verification_status = original_info.get("verification_status", {"verified": False, "confidence": 0})
            verification_text = f"{verification_status.get('confidence', 0):.0f}%"
            if verification_status.get("verified", False):
                verification_text = "✓ " + verification_text
            
            # Set row tags for coloring based on verification
            tags = ()
            if verification_status.get("verified", False):
                tags = ("verified",)
            elif verification_status.get("confidence", 0) < 50:
                tags = ("suspicious",)
            
            # Count pending commands (from both original and current)
            pending_count = len(original_info.get("pending_commands", []))
            if current_id != original_id:
                pending_count += len(current_info.get("pending_commands", []))
            
            # Insert the client row
            self.tree.insert("", tk.END, iid=original_id, values=(
                original_id,  # Original Client ID
                current_id,   # Current Client ID
                current_info.get("ip", "Unknown"),
                hostname,
                username,
                os_version,
                verification_text,
                current_info.get("last_seen", "Unknown"),
                pending_count,
            ), tags=tags)
            
            # Log the client ID chain for debugging if there's a rotation
            if original_id != current_id:
                self.logger(f"Client ID chain: {original_id} -> {current_id}")
        
        # Configure tag colors
        self.tree.tag_configure("verified", background="#e6ffe6")  # Light green
        self.tree.tag_configure("suspicious", background="#ffe6e6")  # Light red

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            self.context_menu.post(event.x_root, event.y_root)

    def open_client_details(self):
        """Open client details view for selected client"""
        selected = self.tree.selection()
        if selected:
            client_id = selected[0]
            self.on_client_select(client_id)

    def request_client_id_rotation(self):
        """Request a client ID rotation for the selected client"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a client first")
            return
            
        client_id = selected[0]
        
        # Check if client is verified first
        client_info = self.client_manager.get_clients_info().get(client_id, {})
        verification_status = client_info.get("verification_status", {})
        
        if not verification_status.get("verified", False):
            messagebox.showwarning("Verification Required", 
                                "Client must be verified before ID rotation can be performed.")
            return
        
        # Ask for confirmation
        result = messagebox.askyesno("Confirm ID Rotation", 
                                    "Are you sure you want to rotate this client's ID?\n\n"
                                    "The client will start using a new identifier after its next beacon.")
        if result:
            # Add the command to the client
            try:
                # First create a temporary instance of ClientHelper to generate the command
                from core.crypto_operations import CryptoHelper
                crypto_helper = CryptoHelper(None, self.client_manager)
                
                # We need the server object - can be None for this purpose
                from core.client_operations import ClientHelper
                client_helper = ClientHelper(self.client_manager, crypto_helper, None)
                
                # Create and add the command
                rotation_cmd = client_helper.prepare_client_id_rotation(client_id)
                self.client_manager.add_command(client_id, rotation_cmd["command_type"], rotation_cmd["args"])
                
                messagebox.showinfo("Success", 
                                f"Client ID rotation command sent to {client_id}.\n"
                                "The client will change its ID on next beacon.")
                
                # Refresh the client list to show the updated status
                self.refresh_client_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to request client ID rotation: {str(e)}")