import tkinter as tk
from tkinter import ttk, messagebox
import datetime
import json

class ClientManager:
    def __init__(self):
        self.clients = {}  # key: client_id, value: dict with keys: last_seen, pending_commands, history

    def add_client(self, client_id):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if client_id not in self.clients:
            self.clients[client_id] = {
                "last_seen": now,
                "pending_commands": [],
                "history": []
            }
        else:
            self.clients[client_id]["last_seen"] = now

    def add_command(self, client_id, command_type, args):
        self.add_client(client_id)  # ensure client exists and update last seen
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
      return self.clients[client_id].get("pending_commands")

    def clear_pending_commands(self, client_id):
      self.clients[client_id]["pending_commands"]=[]

class ClientManagementTab:
    def __init__(self, parent, client_manager):
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager
        self.create_widgets()
        self.refresh_client_list()

    def create_widgets(self):
        # Treeview for active clients
        self.tree = ttk.Treeview(self.frame, columns=("Last Seen", "Pending Commands"), show="headings")
        self.tree.heading("Last Seen", text="Last Seen")
        self.tree.heading("Pending Commands", text="Pending Commands")
        self.tree.column("Last Seen", width=150)
        self.tree.column("Pending Commands", width=120)
        self.tree.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_client_select)

        # Refresh button
        self.btn_refresh = ttk.Button(self.frame, text="Refresh", command=self.refresh_client_list)
        self.btn_refresh.pack(pady=5)

        # Command History display
        ttk.Label(self.frame, text="Command History:").pack(anchor=tk.W, padx=5)
        self.text_history = tk.Text(self.frame, height=10, state="disabled")
        self.text_history.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

        # Add Command form
        ttk.Label(self.frame, text="Add Command to Client:").pack(anchor=tk.W, padx=5, pady=(10,0))
        form_frame = ttk.Frame(self.frame)
        form_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(form_frame, text="Client ID:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.entry_client_id = ttk.Entry(form_frame)
        self.entry_client_id.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(form_frame, text="Command Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.combo_command_type = ttk.Combobox(form_frame, values=["execute", "upload"], state="readonly")
        self.combo_command_type.grid(row=1, column=1, padx=5, pady=2)
        self.combo_command_type.current(0)

        ttk.Label(form_frame, text="Arguments:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.entry_args = ttk.Entry(form_frame)
        self.entry_args.grid(row=2, column=1, padx=5, pady=2)

        self.btn_add_command = ttk.Button(form_frame, text="Add Command", command=self.add_command)
        self.btn_add_command.grid(row=3, column=0, columnspan=2, pady=5)

    def refresh_client_list(self):
        # Clear current tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Insert clients from client_manager
        for client_id, info in self.client_manager.get_clients_info().items():
            pending_count = len(info.get("pending_commands", []))
            self.tree.insert("", tk.END, iid=client_id, values=(info["last_seen"], pending_count), text=client_id)
    
    def on_client_select(self, event):
        selected = self.tree.selection()
        if selected:
            client_id = selected[0]
            history = self.client_manager.get_client_history(client_id)
            self.text_history.config(state="normal")
            self.text_history.delete(1.0, tk.END)
            for cmd in history:
                line = f"{cmd['timestamp']} - {cmd['command_type']} - {cmd['args']}\n"
                self.text_history.insert(tk.END, line)
            self.text_history.config(state="disabled")
            # Also fill the add command form's client id for convenience
            self.entry_client_id.delete(0, tk.END)
            self.entry_client_id.insert(0, client_id)

    def add_command(self):
        client_id = self.entry_client_id.get().strip()
        command_type = self.combo_command_type.get().strip()
        args = self.entry_args.get().strip()
        if not client_id or not command_type or not args:
            messagebox.showerror("Error", "Please fill in all fields for the command.")
            return
        self.client_manager.add_command(client_id, command_type, args)
        messagebox.showinfo("Success", f"Command added for client {client_id}.")
        self.refresh_client_list()
        self.on_client_select(None)  # refresh history display
