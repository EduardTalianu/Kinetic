import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import datetime
import json
from core.cmd import CommandExecutor


class ClientManager:
    def __init__(self):
        # key: client_id, value: dict with keys: last_seen, ip, hostname, pending_commands, history
        self.clients = {}
        self.command_update_callbacks = {}  # Dictionary to store callbacks

    def add_client(self, client_id, ip="Unknown", hostname="Unknown"):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if client_id not in self.clients:
            self.clients[client_id] = {
                "last_seen": now,
                "ip": ip,
                "hostname": hostname,
                "pending_commands": [],
                "history": []
            }
        else:
            self.clients[client_id]["last_seen"] = now
            self.clients[client_id]["ip"] = ip
            self.clients[client_id]["hostname"] = hostname

    def add_command(self, client_id, command_type, args, ip="Unknown", hostname="Unknown"):
        self.add_client(client_id, ip, hostname)
        command = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": command_type,
            "args": args
        }
        self.clients[client_id]["pending_commands"].append(command)
        self.clients[client_id]["history"].append(command)

    def get_clients_info(self):
        return self.clients

    def get_client_history(self, client_id):
        return self.clients.get(client_id, {}).get("history", [])

    def get_pending_commands(self, client_id):
        return self.clients.get(client_id, {}).get("pending_commands", [])

    def clear_pending_commands(self, client_id):
        if client_id in self.clients:
            self.clients[client_id]["pending_commands"] = []

    def register_command_update_callback(self, client_id, callback):
        """Registers a callback to be called when a command result is updated."""
        self.command_update_callbacks.setdefault(client_id, []).append(callback)

    def on_command_updated(self, client_id):
        """Calls all registered callbacks for the given client."""
        for callback in self.command_update_callbacks.get(client_id, []):
            callback()


class ClientManagementTab:
    def __init__(self, parent, client_manager):
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager
        self.executor = CommandExecutor(self.client_manager)  # Start command executor
        self.notebook = ttk.Notebook(self.frame)  # Notebook to hold client details tabs
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.client_list_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.client_list_frame, text="Client List")

        self.create_widgets()
        self.refresh_client_list()

        self.client_details_tabs = {}  # Keep track of client details tabs

    def create_widgets(self):
        # Treeview for active clients with enhanced columns
        columns = ("Client ID", "IP", "Hostname", "Last Seen", "Pending Commands")
        self.tree = ttk.Treeview(self.client_list_frame, columns=columns, show="headings")
        self.tree.heading("Client ID", text="Client ID")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("Last Seen", text="Last Seen")
        self.tree.heading("Pending Commands", text="Pending Commands")

        # Adjust column widths
        self.tree.column("Client ID", width=100)
        self.tree.column("IP", width=120)
        self.tree.column("Hostname", width=120)
        self.tree.column("Last Seen", width=150)
        self.tree.column("Pending Commands", width=100)

        self.tree.pack(fill=tk.BOTH, padx=5, pady=5, expand=True, in_=self.client_list_frame)

        # Right-click context menu
        self.context_menu = tk.Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="Add Command: whoami", command=self.add_whoami_command)
        self.context_menu.add_command(label="Add Custom Command", command=self.add_custom_command)
        self.context_menu.add_command(label="View Details", command=self.open_client_details_tab)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Refresh button
        self.btn_refresh = ttk.Button(self.client_list_frame, text="Refresh", command=self.refresh_client_list)
        self.btn_refresh.pack(pady=5, in_=self.client_list_frame)

    def refresh_client_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for client_id, info in self.client_manager.get_clients_info().items():
            pending_count = len(info.get("pending_commands", []))

            self.tree.insert("", tk.END, iid=client_id, values=(
                client_id,
                info["ip"],
                info["hostname"],
                info["last_seen"],
                pending_count,
            ))

    def show_context_menu(self, event):
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            self.context_menu.post(event.x_root, event.y_root)

    def add_whoami_command(self):
        selected = self.tree.selection()
        if selected:
            client_id = selected[0]
            self.client_manager.add_command(client_id, "execute", "whoami")
            messagebox.showinfo("Success", f"Command 'whoami' queued for client {client_id}.")
            self.refresh_client_list()

    def add_custom_command(self):
        selected = self.tree.selection()
        if selected:
            client_id = selected[0]
            dialog = tk.Toplevel(self.frame)
            dialog.title("Add Custom Command")
            dialog.geometry("300x150")
            dialog.transient(self.frame)
            dialog.grab_set()

            ttk.Label(dialog, text="Command Type:").pack(pady=5)
            combo_command_type = ttk.Combobox(dialog, values=["execute", "upload"], state="readonly")
            combo_command_type.pack()
            combo_command_type.current(0)

            ttk.Label(dialog, text="Arguments:").pack(pady=5)
            entry_args = ttk.Entry(dialog)
            entry_args.pack()

            def submit_command():
                command_type = combo_command_type.get().strip()
                args = entry_args.get().strip()
                if not command_type or not args:
                    messagebox.showerror("Error", "Please fill in both fields.")
                    return
                self.client_manager.add_command(client_id, command_type, args)
                messagebox.showinfo("Success", f"Command queued for client {client_id}.")
                self.refresh_client_list()
                dialog.destroy()

            ttk.Button(dialog, text="Submit", command=submit_command).pack(pady=10)

    def open_client_details_tab(self):
        selected = self.tree.selection()
        if selected:
            client_id = selected[0]
            self.create_client_details_tab(client_id)

    def create_client_details_tab(self, client_id):
        # Check if the tab already exists
        if client_id in self.client_details_tabs:
            self.notebook.select(self.client_details_tabs[client_id]["frame"])
            return

        details_frame = ttk.Frame(self.notebook)
        self.notebook.add(details_frame, text=f"Client {client_id} Details")
        self.notebook.select(details_frame)  # Open the new tab

        client_info = self.client_manager.get_clients_info().get(client_id, {})
        history = client_info.get("history", [])

        # Display Client Info
        info_label = ttk.Label(details_frame,
                               text=f"IP: {client_info.get('ip', 'N/A')} | Hostname: {client_info.get('hostname', 'N/A')} | Last Seen: {client_info.get('last_seen', 'N/A')}")
        info_label.pack(pady=5)

        # Treeview for Command History
        columns = ("Timestamp", "Arguments", "Result")  # Removed "Command Type"
        history_tree = ttk.Treeview(details_frame, columns=columns, show="headings")
        history_tree.heading("Timestamp", text="Timestamp")
        history_tree.heading("Arguments", text="Arguments")
        history_tree.heading("Result", text="Result")

        # Adjust column widths, make Result column stretchable
        history_tree.column("Timestamp", width=150)
        history_tree.column("Arguments", width=150)
        history_tree.column("Result", width=400, stretch=True) #changed width and added stretch

        history_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create a scrolled text widget for displaying detailed result
        self.result_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bind a function to handle selection change
        history_tree.bind("<ButtonRelease-1>", lambda event, tree=history_tree: self.on_select_command(event, tree))
        history_tree.bind("<Return>", lambda event, tree=history_tree: self.on_select_command(event, tree))

        self.populate_history_tree(client_id, history_tree)

        # Store history_tree and frame for later access
        self.client_details_tabs[client_id] = {"frame": details_frame, "tree": history_tree}
        # Register the callback to update the history tree
        self.client_manager.register_command_update_callback(client_id,
                                                              lambda: self.update_client_history_tree(client_id))

    def populate_history_tree(self, client_id, history_tree):
        """Populates the history tree with the client's command history."""
        history_tree.delete(*history_tree.get_children())  # Clear the tree
        history = self.client_manager.get_client_history(client_id)
        for command in history:
            history_tree.insert("", tk.END, values=(
                command["timestamp"],
                command["args"],
                command.get("result", "Pending")
            ))

    def update_client_history_tree(self, client_id):
        """Updates the client's history tree."""
        if client_id in self.client_details_tabs:
            history_tree = self.client_details_tabs[client_id]["tree"]
            self.populate_history_tree(client_id, history_tree)

    def on_select_command(self, event, tree):
        """Displays the details of the selected command in the ScrolledText widget."""
        selected_item = tree.selection()
        if selected_item:
            item_values = tree.item(selected_item, 'values')
            # Extract timestamp and find the detailed result from the client history
            timestamp = item_values[0]
            client_id = self.get_client_id_from_tab_title(tree)
            if client_id is None:
              return
            client_history = self.client_manager.get_client_history(client_id)
            for command in client_history:
                if command['timestamp'] == timestamp:
                    result = command.get('result', 'No result available')
                    # Display result in the ScrolledText widget
                    self.result_text.config(state=tk.NORMAL)
                    self.result_text.delete("1.0", tk.END)
                    self.result_text.insert(tk.END, result)
                    self.result_text.config(state=tk.DISABLED)
                    break

    def get_client_id_from_tab_title(self, tree):
      """Extracts the client_id from the tab title."""
      for client_id, tab_data in self.client_details_tabs.items():
          if tab_data["tree"] == tree:
              return client_id
      return None
