import tkinter as tk
from tkinter import ttk, messagebox

class ClientListUI:
    """Handles the UI components for displaying the client list"""
    
    def __init__(self, parent_frame, client_manager, logger, on_client_select):
        """
        Initialize the client list UI handler
        
        Args:
            parent_frame: The parent frame widget
            client_manager: The client manager instance
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
        # Treeview for active clients with enhanced columns
        columns = ("Client ID", "IP", "Hostname", "Username", "OS Version", "Verification", "Last Seen", "Pending Commands")
        self.tree = ttk.Treeview(self.parent_frame, columns=columns, show="headings")
        self.tree.heading("Client ID", text="Client ID")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("Username", text="Username")
        self.tree.heading("OS Version", text="OS Version")
        self.tree.heading("Verification", text="Verification")
        self.tree.heading("Last Seen", text="Last Seen")
        self.tree.heading("Pending Commands", text="Pending Commands")

        # Adjust column widths
        self.tree.column("Client ID", width=100)
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

        # Right-click context menu - simplified to only include View Details
        self.context_menu = tk.Menu(self.parent_frame, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.open_client_details)
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
        """Refresh the client list display"""
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for client_id, info in self.client_manager.get_clients_info().items():
            pending_count = len(info.get("pending_commands", []))
            
            # Get verification status
            verification_status = info.get("verification_status", {"verified": False, "confidence": 0})
            verification_text = f"{verification_status.get('confidence', 0):.0f}%"
            if verification_status.get("verified", False):
                verification_text = "✓ " + verification_text
            
            # Set row tags for coloring based on verification
            tags = ()
            if verification_status.get("verified", False):
                tags = ("verified",)
            elif verification_status.get("confidence", 0) < 50:
                tags = ("suspicious",)

            # Fetch additional information with fallbacks
            hostname = info.get("hostname", "Unknown")
            username = info.get("username", "Unknown")
            os_version = info.get("os_version", "Unknown")
            
            # Try to get from system_info if not available at top level
            if hostname == "Unknown" and "system_info" in info:
                hostname = info["system_info"].get("Hostname", "Unknown")
                
            if username == "Unknown" and "system_info" in info:
                username = info["system_info"].get("Username", "Unknown")
                
            if os_version == "Unknown" and "system_info" in info:
                os_version = info["system_info"].get("OsVersion", "Unknown")
            
            # Insert the client row
            self.tree.insert("", tk.END, iid=client_id, values=(
                client_id,
                info.get("ip", "Unknown"),
                hostname,
                username,
                os_version,
                verification_text,
                info.get("last_seen", "Unknown"),
                pending_count,
            ), tags=tags)
        
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