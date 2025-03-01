import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
from core.utils.client_interaction import ClientInteractionUI

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

        # Store history_tree and frame for later access
        self.client_details_tabs[client_id] = {
            "frame": details_frame, 
            "tree": history_tree,
            "notebook": client_notebook,
            "interaction": self.client_interaction
        }
        
        # Register the callback to update the history tree
        self.client_manager.register_command_update_callback(client_id,
                                                             lambda: self.update_client_history_tree(client_id))
    
    def close_client_tab(self, client_id):
        """Close the client details tab"""
        if client_id in self.client_details_tabs:
            tab_frame = self.client_details_tabs[client_id]["frame"]
            tab_index = self.notebook.index(tab_frame)
            self.notebook.forget(tab_index)
            del self.client_details_tabs[client_id]

    def populate_system_info_tab(self, parent_frame, client_info):
        """Populate the system information tab with client details"""
        # Create scrollable canvas for system info
        canvas = tk.Canvas(parent_frame, width=600)  # 30% wider (from approx. 462 to 600)
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
        
        # Two-column layout for basic info with increased width
        labels = [
            ("Client ID:", client_info.get("client_id", "Unknown")),
            ("IP Address:", client_info.get("ip", "Unknown")),
            ("Hostname:", client_info.get("hostname", "Unknown")),
            ("Username:", client_info.get("username", "Unknown")),
            ("Machine GUID:", client_info.get("machine_guid", "Unknown")),
            ("OS Version:", client_info.get("os_version", "Unknown")),
            ("MAC Address:", client_info.get("mac_address", "Unknown")),
            ("Last Seen:", client_info.get("last_seen", "Unknown"))
        ]
        
        for i, (label, value) in enumerate(labels):
            ttk.Label(basic_frame, text=label, width=15, anchor="e").grid(row=i//2, column=i%2*2, sticky="e", padx=5, pady=2)
            value_text = ttk.Label(basic_frame, text=value, width=32, anchor="w")  # Increased from 25 to 32
            value_text.grid(row=i//2, column=i%2*2+1, sticky="w", padx=5, pady=2)
            
        # Advanced system information section
        if "system_info" in client_info and client_info["system_info"]:
            advanced_frame = ttk.LabelFrame(scroll_frame, text="Advanced System Information")
            advanced_frame.pack(fill=tk.X, padx=10, pady=5, anchor="n")
            
            row = 0
            for key, value in client_info["system_info"].items():
                # Skip keys already shown in basic info
                if key.lower() not in ["hostname", "username", "machineguid", "osversion", "macaddress"]:
                    ttk.Label(advanced_frame, text=f"{key}:", width=15, anchor="e").grid(row=row, column=0, sticky="e", padx=5, pady=2)
                    
                    # Handle different value types
                    if isinstance(value, dict):
                        value_str = json.dumps(value, indent=2)
                    elif isinstance(value, list):
                        value_str = ", ".join(str(item) for item in value)
                    else:
                        value_str = str(value)
                    
                    value_text = ttk.Label(advanced_frame, text=value_str, wraplength=400, anchor="w")  # Increased from 300 to 400
                    value_text.grid(row=row, column=1, sticky="w", padx=5, pady=2)
                    row += 1

    def populate_verification_tab(self, parent_frame, client_info):
        """Populate the verification tab with identity verification information"""
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
        
        # Warnings section
        warnings_frame = ttk.LabelFrame(parent_frame, text="Verification Warnings")
        warnings_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
        
        warnings = verification_status.get("warnings", [])
        if warnings:
            for warning in warnings:
                ttk.Label(warnings_frame, text=f"• {warning}", foreground="#FF4500").pack(anchor="w", padx=10, pady=2)
        else:
            ttk.Label(warnings_frame, text="No verification warnings", foreground="#008000").pack(anchor="w", padx=10, pady=2)
        
        # Explanation section
        explanation_frame = ttk.LabelFrame(parent_frame, text="About Verification")
        explanation_frame.pack(fill=tk.X, padx=10, pady=10)
        
        explanation_text = """
        Client verification uses multiple system identifiers to verify that a client is who they claim to be. 
        The confidence score is calculated based on the stability of identifiers like:
        
        • Machine GUID (most important)
        • MAC address
        • Hostname and username
        • OS version and hardware information
        
        A confidence score above 70% is considered verified. Warning signs include changes to critical identifiers.
        """
        
        explanation_label = ttk.Label(explanation_frame, text=explanation_text, wraplength=400, justify=tk.LEFT)
        explanation_label.pack(padx=10, pady=10)

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

            self.tree.insert("", tk.END, iid=client_id, values=(
                client_id,
                info["ip"],
                info["hostname"],
                info.get("username", "Unknown"),
                info.get("os_version", "Unknown"),
                verification_text,
                info["last_seen"],
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


class CommandDialogUI:
    """Helper class for creating command dialogs"""
    
    @staticmethod
    def create_command_dialog(parent, client_id, client_manager, callback=None):
        """
        Create a dialog for entering a custom command
        
        Args:
            parent: The parent widget
            client_id: The client ID to send the command to
            client_manager: The client manager instance
            callback: Optional callback after command is submitted
        """
        dialog = tk.Toplevel(parent)
        dialog.title("Add Custom Command")
        dialog.geometry("400x200")
        dialog.transient(parent)
        dialog.grab_set()

        ttk.Label(dialog, text="Command Type:").pack(pady=5)
        combo_command_type = ttk.Combobox(
            dialog, 
            values=["execute", "upload", "download", "screenshot", "system_info"], 
            state="readonly"
        )
        combo_command_type.pack(fill=tk.X, padx=10)
        combo_command_type.current(0)

        ttk.Label(dialog, text="Arguments:").pack(pady=5)
        entry_args = ttk.Entry(dialog, width=50)
        entry_args.pack(fill=tk.X, padx=10)

        # Command description area
        ttk.Label(dialog, text="Command Description:").pack(pady=5)
        description_frame = ttk.Frame(dialog)
        description_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        description_text = tk.Text(description_frame, height=3, wrap=tk.WORD)
        description_text.pack(fill=tk.BOTH, expand=True)
        
        # Update description based on command type
        def update_description(*args):
            cmd_type = combo_command_type.get()
            description_text.delete("1.0", tk.END)
            
            descriptions = {
                "execute": "Execute a shell command on the client machine.",
                "upload": "Upload a file from the client. Provide the full path to the file.",
                "download": "Download a file to the client. Provide the URL to download from.",
                "screenshot": "Take a screenshot on the client machine.",
                "system_info": "Collect detailed system information from the client."
            }
            
            description_text.insert(tk.END, descriptions.get(cmd_type, "No description available"))
            
            # Enable/disable args entry based on command type
            if cmd_type in ["screenshot", "system_info"]:
                entry_args.delete(0, tk.END)
                entry_args.config(state="disabled")
            else:
                entry_args.config(state="normal")
        
        combo_command_type.bind("<<ComboboxSelected>>", update_description)
        update_description()  # Initial description

        def submit_command():
            command_type = combo_command_type.get().strip()
            args = entry_args.get().strip()
            
            if not command_type:
                messagebox.showerror("Error", "Please select a command type.")
                return
                
            if command_type not in ["screenshot", "system_info"] and not args:
                messagebox.showerror("Error", "Please provide command arguments.")
                return
                
            client_manager.add_command(client_id, command_type, args)
            messagebox.showinfo("Success", f"Command queued for client {client_id}.")
            dialog.destroy()
            
            if callback:
                callback()

        ttk.Button(dialog, text="Submit", command=submit_command).pack(pady=10)