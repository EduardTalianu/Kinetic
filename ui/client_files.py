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
        
        ttk.Label(upload_control_frame, text="Local File:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.upload_file_path = ttk.Entry(upload_control_frame, width=40)
        self.upload_file_path.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Button(upload_control_frame, text="Browse", 
                  command=self.browse_local_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Add destination path field
        ttk.Label(upload_control_frame, text="Destination:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.upload_destination_path = ttk.Entry(upload_control_frame, width=40)
        self.upload_destination_path.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Default to %TEMP% directory for uploads
        self.upload_destination_path.insert(0, "%TEMP%\\")
        
        # Destination path dropdown for common locations
        upload_destinations = ["%TEMP%\\", "%USERPROFILE%\\Desktop\\", "%USERPROFILE%\\Documents\\", 
                             "C:\\Windows\\Temp\\", "C:\\Users\\Public\\Documents\\"]
        self.upload_dest_combo = ttk.Combobox(upload_control_frame, values=upload_destinations, width=15)
        self.upload_dest_combo.grid(row=1, column=2, padx=5, pady=5)
        self.upload_dest_combo.bind("<<ComboboxSelected>>", self.on_upload_dest_selected)
        
        # Upload button with clearer name
        ttk.Button(upload_control_frame, text="Upload to Client", 
                  command=self.upload_file_to_client).grid(row=2, column=1, padx=5, pady=5)
        
        # Upload history
        upload_history_frame = ttk.Frame(self.upload_frame)
        upload_history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(upload_history_frame, text="Upload History:").pack(anchor=tk.W, padx=5, pady=2)
        
        # Treeview for upload history
        columns = ("Timestamp", "Filename", "Destination", "Size", "Status")
        self.upload_tree = ttk.Treeview(upload_history_frame, columns=columns, show="headings", height=5)
        
        self.upload_tree.heading("Timestamp", text="Timestamp")
        self.upload_tree.heading("Filename", text="Filename")
        self.upload_tree.heading("Destination", text="Destination")
        self.upload_tree.heading("Size", text="Size")
        self.upload_tree.heading("Status", text="Status")
        
        # Configure column widths
        self.upload_tree.column("Timestamp", width=150)
        self.upload_tree.column("Filename", width=150)
        self.upload_tree.column("Destination", width=200)
        self.upload_tree.column("Size", width=80)
        self.upload_tree.column("Status", width=80)
        
        # Add scrollbar for upload tree
        upload_scrollbar = ttk.Scrollbar(upload_history_frame, orient="vertical", command=self.upload_tree.yview)
        self.upload_tree.configure(yscrollcommand=upload_scrollbar.set)
        
        # Pack tree and scrollbar
        self.upload_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        upload_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # === DOWNLOAD SECTION (Client to Server) ===
        download_control_frame = ttk.Frame(self.download_frame)
        download_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(download_control_frame, text="Remote File Path:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.remote_file_path = ttk.Entry(download_control_frame, width=40)
        self.remote_file_path.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Button(download_control_frame, text="Download from Client", 
                  command=self.download_file_from_client).grid(row=0, column=2, padx=5, pady=5)
        
        # Remote file browsing
        browse_remote_frame = ttk.Frame(self.download_frame)
        browse_remote_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(browse_remote_frame, text="Browse Location:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        remote_dir_combo_values = ["C:\\Users\\Public\\Documents", "C:\\Windows\\Temp", "%USERPROFILE%\\Downloads", 
                                  "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "C:\\"]
        self.remote_dir_combo = ttk.Combobox(browse_remote_frame, values=remote_dir_combo_values, width=30)
        self.remote_dir_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.remote_dir_combo.bind("<<ComboboxSelected>>", self.on_remote_dir_selected)
        
        ttk.Button(browse_remote_frame, text="List Directory", 
                  command=lambda: self.download_directory_listing(self.remote_dir_combo.get())).grid(row=0, column=2, padx=5, pady=5)
        
        # Drive info button - uses Get-DriveInfo function
        ttk.Button(browse_remote_frame, text="List Drives", 
                 command=self.get_drive_info).grid(row=1, column=0, padx=5, pady=5)
        
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
        self.download_tree.column("Remote Path", width=180)
        self.download_tree.column("Local Path", width=180)
        self.download_tree.column("Size", width=80)
        self.download_tree.column("Status", width=80)
        
        # Add scrollbar for download tree
        download_scrollbar = ttk.Scrollbar(download_history_frame, orient="vertical", command=self.download_tree.yview)
        self.download_tree.configure(yscrollcommand=download_scrollbar.set)
        
        # Pack tree and scrollbar
        self.download_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        download_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File preview area
        preview_frame = ttk.LabelFrame(self.main_frame, text="Directory Listing / File Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add directory listing mode controls
        preview_controls = ttk.Frame(preview_frame)
        preview_controls.pack(fill=tk.X, padx=5, pady=2)
        
        self.preview_mode = tk.StringVar(value="table")
        ttk.Radiobutton(preview_controls, text="Table View", variable=self.preview_mode, 
                       value="table", command=self.refresh_preview).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(preview_controls, text="Raw View", variable=self.preview_mode, 
                       value="raw", command=self.refresh_preview).pack(side=tk.LEFT, padx=5)
        
        self.preview_text = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD, height=8)
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Directory listing treeview
        self.dir_listing_frame = ttk.Frame(preview_frame)
        self.dir_listing_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a treeview for directory listing
        columns = ("Name", "Type", "Size", "Modified", "Attributes")
        self.dir_tree = ttk.Treeview(self.dir_listing_frame, columns=columns, show="headings", height=8)
        
        self.dir_tree.heading("Name", text="Name")
        self.dir_tree.heading("Type", text="Type")
        self.dir_tree.heading("Size", text="Size")
        self.dir_tree.heading("Modified", text="Modified")
        self.dir_tree.heading("Attributes", text="Attributes")
        
        # Configure column widths
        self.dir_tree.column("Name", width=200)
        self.dir_tree.column("Type", width=80)
        self.dir_tree.column("Size", width=80)
        self.dir_tree.column("Modified", width=150)
        self.dir_tree.column("Attributes", width=100)
        
        # Add scrollbar for directory tree
        dir_scrollbar = ttk.Scrollbar(self.dir_listing_frame, orient="vertical", command=self.dir_tree.yview)
        self.dir_tree.configure(yscrollcommand=dir_scrollbar.set)
        
        # Pack tree and scrollbar
        self.dir_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dir_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add right-click context menu to directory tree
        self.dir_context_menu = tk.Menu(self.dir_tree, tearoff=0)
        self.dir_context_menu.add_command(label="Download Selected", command=self.download_selected_file)
        self.dir_context_menu.add_command(label="Navigate to Directory", command=self.navigate_to_selected_dir)
        self.dir_tree.bind("<Button-3>", self.show_dir_context_menu)
        
        # Double-click to navigate or download
        self.dir_tree.bind("<Double-1>", self.on_dir_item_double_click)
        
        # Hide directory listing by default - show text area instead
        self.dir_listing_frame.pack_forget()
        
        # Bind selection events to display file info
        self.download_tree.bind("<<TreeviewSelect>>", self.on_download_select)
        self.upload_tree.bind("<<TreeviewSelect>>", self.on_upload_select)
        
        # Control buttons at the bottom
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_files_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Open Downloads Folder", command=self.open_downloads_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear History", command=self.clear_history).pack(side=tk.LEFT, padx=5)
        
        # Current working directory indicator
        self.cwd_var = tk.StringVar(value="Current path: Not set")
        ttk.Label(control_frame, textvariable=self.cwd_var).pack(side=tk.RIGHT, padx=5)
    
    def show_dir_context_menu(self, event):
        """Show context menu on right-click in directory tree"""
        # Select the item under the cursor
        item = self.dir_tree.identify_row(event.y)
        if item:
            self.dir_tree.selection_set(item)
            self.dir_context_menu.post(event.x_root, event.y_root)
    
    def download_selected_file(self):
        """Download the selected file from directory listing"""
        selected = self.dir_tree.selection()
        if not selected:
            return
        
        # Get the selected item data
        item_values = self.dir_tree.item(selected[0], 'values')
        if not item_values:
            return
        
        # Get file name and current directory
        file_name = item_values[0]
        file_type = item_values[1]
        
        # Only proceed if it's a file, not a directory
        if file_type.lower() != "file":
            messagebox.showinfo("Selection Error", "Please select a file to download, not a directory.")
            return
        
        # Get current directory from the cwd_var or use empty string
        current_dir = self.cwd_var.get().replace("Current path: ", "")
        if not current_dir or current_dir == "Not set":
            messagebox.showerror("Error", "Current directory not set. Please browse to a directory first.")
            return
        
        # Create full path
        full_path = os.path.join(current_dir, file_name)
        
        # Set the remote file path
        self.remote_file_path.delete(0, tk.END)
        self.remote_file_path.insert(0, full_path)
        
        # Download the file
        self.download_file_from_client()

    def navigate_to_selected_dir(self):
        """Navigate to the selected directory in the directory listing"""
        selected = self.dir_tree.selection()
        if not selected:
            return
        
        # Get the selected item data
        item_values = self.dir_tree.item(selected[0], 'values')
        if not item_values:
            return
        
        # Get directory name and type
        dir_name = item_values[0]
        dir_type = item_values[1]
        
        # Only proceed if it's a directory
        if dir_type.lower() != "directory":
            messagebox.showinfo("Selection Error", "Please select a directory to navigate to, not a file.")
            return
        
        # Get current directory from the cwd_var or use empty string
        current_dir = self.cwd_var.get().replace("Current path: ", "")
        if not current_dir or current_dir == "Not set":
            messagebox.showerror("Error", "Current directory not set. Please browse to a directory first.")
            return
        
        # Create full path
        new_path = os.path.join(current_dir, dir_name)
        
        # Update the remote directory combo and browse to it
        self.remote_dir_combo.set(new_path)
        self.download_directory_listing(new_path)
    
    def on_dir_item_double_click(self, event):
        """Handle double-click on directory item - navigate or download"""
        selected = self.dir_tree.selection()
        if not selected:
            return
        
        # Get the selected item data
        item_values = self.dir_tree.item(selected[0], 'values')
        if not item_values:
            return
        
        # Get name and type
        name = item_values[0]
        item_type = item_values[1]
        
        if item_type.lower() == "directory":
            # Navigate to directory
            self.navigate_to_selected_dir()
        else:
            # Download file
            self.download_selected_file()
    
    def refresh_preview(self):
        """Refresh preview based on selected mode"""
        mode = self.preview_mode.get()
        
        if mode == "table":
            # Show directory listing table, hide text
            self.preview_text.pack_forget()
            self.dir_listing_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            # Show text preview, hide directory table
            self.dir_listing_frame.pack_forget()
            self.preview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def get_drive_info(self):
        """Get drive information from the client"""
        # Send the command to get drive info
        self.client_manager.add_command(self.client_id, "execute", "Get-DriveInfo")
        
        # Show a message
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, "Requesting drive information...\n")
        
        # Log the request
        self.logger(f"Requesting drive information from client {self.client_id}")
    
    def browse_local_file(self):
        """Open file dialog to select a local file to upload"""
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if file_path:
            self.upload_file_path.delete(0, tk.END)
            self.upload_file_path.insert(0, file_path)
    
    def on_upload_dest_selected(self, event):
        """Handle selection of upload destination from dropdown"""
        selected_dest = self.upload_dest_combo.get()
        if selected_dest:
            self.upload_destination_path.delete(0, tk.END)
            self.upload_destination_path.insert(0, selected_dest)
    
    def upload_file_to_client(self):
        """Upload a file from the local machine to the client"""
        local_file_path = self.upload_file_path.get().strip()
        destination_path = self.upload_destination_path.get().strip()
        
        if not local_file_path:
            messagebox.showerror("Error", "Please select a file to upload")
            return
        
        if not os.path.exists(local_file_path):
            messagebox.showerror("Error", "File does not exist")
            return
        
        if not destination_path:
            messagebox.showerror("Error", "Please specify a destination path")
            return
        
        # Get file size for display
        file_size = os.path.getsize(local_file_path)
        file_size_str = self.format_file_size(file_size)
        
        # Create command to upload the file using our custom function
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        command_args = f"Upload-File -SourcePath '{local_file_path}' -DestinationPath '{destination_path}'"
        
        # Add command to client manager
        self.client_manager.add_command(self.client_id, "execute", command_args)
        
        # Add to upload history
        upload_id = f"upload_{timestamp}"
        self.uploaded_files[upload_id] = {
            "timestamp": timestamp,
            "local_path": local_file_path,
            "remote_path": destination_path,
            "filename": os.path.basename(local_file_path),
            "size": file_size_str,
            "status": "Pending"
        }
        
        # Update the tree
        self.update_upload_tree()
        
        # Log the upload
        self.logger(f"File upload initiated: {local_file_path} to {self.client_id}:{destination_path}")
        messagebox.showinfo("Upload Started", f"File upload initiated: {os.path.basename(local_file_path)}\nDestination: {destination_path}")

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
        
        # Use the Download-File function we added
        command_args = f"Download-File -FilePath '{remote_path}'"
        self.client_manager.add_command(self.client_id, "execute", command_args)
        
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
        messagebox.showinfo("Download Started", f"File download initiated from: {remote_path}")

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
        
        # Save the current directory in the UI
        self.cwd_var.set(f"Current path: {display_dir}")
        
        # Create command for directory listing
        # Using Get-DirectoryListing function for better formatting
        command_args = f"Get-DirectoryListing -DirectoryPath '{directory}'"
        self.client_manager.add_command(self.client_id, "execute", command_args)
        
        # Set the preview text and ensure raw view is displayed
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, f"Getting directory listing for {display_dir}...\n")
        
        # Switch to table view for directory listing
        self.preview_mode.set("table")
        self.refresh_preview()
        
        # Log the request
        self.logger(f"Requesting directory listing: {self.client_id}:{display_dir}")
    
    def on_remote_dir_selected(self, event):
        """Handle selection of a remote directory from the dropdown"""
        selected_dir = self.remote_dir_combo.get()
        if selected_dir:
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
                if command_type == "execute" and "Download-File" in args and timestamp:
                    download_id = f"download_{timestamp}"
                    if download_id in self.downloaded_files:
                        download_info = self.downloaded_files[download_id]
                        
                        # Check if result indicates success
                        if "Successfully downloaded" in result or "bytes" in result:
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
                elif command_type == "execute" and "Upload-File" in args and timestamp:
                    upload_id = f"upload_{timestamp}"
                    if upload_id in self.uploaded_files:
                        upload_info = self.uploaded_files[upload_id]
                        
                        # Check if result indicates success
                        if "Successfully" in result or "uploaded" in result:
                            upload_info["status"] = "Completed"
                        elif "Error" in result or "failed" in result:
                            upload_info["status"] = "Failed"
                            upload_info["error"] = result
                
                # Handle directory listing results
                elif command_type == "execute" and "Get-DirectoryListing" in args:
                    try:
                        # Try to parse JSON output
                        self.display_directory_listing(result, args)
                    except Exception as e:
                        # If there's an error parsing the JSON, just show the raw output
                        self.preview_text.delete(1.0, tk.END)
                        self.preview_text.insert(tk.END, f"Directory Listing Results:\n\n{result}")
                        self.logger(f"Error parsing directory listing: {e}")
                
                # Handle drive info results
                elif command_type == "execute" and "Get-DriveInfo" in args:
                    try:
                        # Try to parse JSON output
                        self.display_drive_info(result)
                    except Exception as e:
                        # If there's an error parsing the JSON, just show the raw output
                        self.preview_text.delete(1.0, tk.END)
                        self.preview_text.insert(tk.END, f"Drive Information Results:\n\n{result}")
                        self.logger(f"Error parsing drive info: {e}")
        
        # Update the UI
        self.update_upload_tree()
        self.update_download_tree()
    
    def display_drive_info(self, result):
        """Display drive information in the preview area"""
        self.preview_mode.set("raw")  # Switch to raw view for drive info
        self.refresh_preview()
        
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, "Available Drives:\n\n")
        
        try:
            # Parse the JSON
            drives = json.loads(result)
            
            # Format as a table
            header = f"{'Drive':<8} {'Type':<10} {'Volume Name':<20} {'Size':<10} {'Free':<10} {'% Free':<8}\n"
            separator = "-" * 70 + "\n"
            
            self.preview_text.insert(tk.END, header)
            self.preview_text.insert(tk.END, separator)
            
            for drive in drives:
                drive_letter = drive.get('DriveLetter', '')
                drive_type = drive.get('DriveType', '')
                volume_name = drive.get('VolumeName', '')
                size_gb = drive.get('SizeGB', 0)
                free_gb = drive.get('FreeSpaceGB', 0)
                percent_free = drive.get('PercentFree', 0)
                
                line = f"{drive_letter:<8} {drive_type:<10} {volume_name:<20} {size_gb:<10.2f} {free_gb:<10.2f} {percent_free:<8.2f}%\n"
                self.preview_text.insert(tk.END, line)
            
            self.preview_text.insert(tk.END, "\nTo navigate to a drive, select it from the dropdown or enter the path manually.")
            
            # Update the dropdown with drives
            drive_values = self.remote_dir_combo['values']
            for drive in drives:
                drive_letter = drive.get('DriveLetter', '')
                if drive_letter and drive_letter + "\\" not in drive_values:
                    drive_values = (*drive_values, drive_letter + "\\")
            
            self.remote_dir_combo['values'] = drive_values
            
        except Exception as e:
            # If there's an error parsing the JSON, just show the raw output
            self.preview_text.insert(tk.END, f"Error parsing drive information: {e}\n\nRaw result:\n{result}")
    
    def display_directory_listing(self, listing_result, command):
        """Display a formatted directory listing in the preview text area and treeview"""
        # Extract directory path from command
        directory = command.split("'")[1] if "'" in command else "Unknown"
        
        # Update the UI based on preview mode
        self.refresh_preview()
        
        # Clear the tree
        for item in self.dir_tree.get_children():
            self.dir_tree.delete(item)
        
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, f"Directory Listing for: {directory}\n\n")
        
        try:
            # Parse JSON
            listing = json.loads(listing_result)
            
            # If the result is a single object, convert to list
            if isinstance(listing, dict):
                listing = [listing]
            
            # Sort listing - directories first, then files alphabetically
            sorted_listing = sorted(listing, key=lambda x: (0 if x.get('Type', '') == 'Directory' else 1, x.get('Name', '')))
            
            # Add parent directory entry for navigation
            if directory and directory not in ["C:\\", "\\"]:
                # Add ".." entry for going up one level
                parent_dir = os.path.dirname(directory)
                if parent_dir:
                    self.dir_tree.insert("", "end", values=("..", "Directory", "", "", ""), tags=("parent",))
            
            # Process each item
            for item in sorted_listing:
                try:
                    name = item.get('Name', 'Unknown')
                    size = item.get('Length', 0)
                    item_type = item.get('Type', '')
                    modified = item.get('LastWriteTime', '')
                    attributes = item.get('Attributes', '')
                    
                    # Handle .NET date format if needed
                    if isinstance(modified, dict) and 'DateTime' in modified:
                        modified = modified['DateTime']
                    
                    # Format size for display
                    if size and item_type.lower() != 'directory':
                        size_str = self.format_file_size(size)
                    else:
                        size_str = ""
                    
                    # Add to treeview
                    self.dir_tree.insert("", "end", values=(name, item_type, size_str, modified, attributes), 
                                       tags=(item_type.lower(),))
                    
                    # Add to text preview as well
                    self.preview_text.insert(tk.END, f"{name:<40} {item_type:<12} {size_str:<12} {modified}\n")
                    
                except Exception as e:
                    self.logger(f"Error processing directory item: {e}")
            
            # Configure tag colors
            self.dir_tree.tag_configure("directory", background="#E5F3FF")
            self.dir_tree.tag_configure("parent", background="#F0F0F0")
            
            # Add instructions to text preview
            self.preview_text.insert(tk.END, "\n\nTo download a file, double-click on it or right-click and select 'Download Selected'.\n")
            self.preview_text.insert(tk.END, "To navigate to a directory, double-click on it or right-click and select 'Navigate to Directory'.")
            
        except json.JSONDecodeError as e:
            # If it's not JSON, display as raw text
            self.preview_text.insert(tk.END, listing_result)
            self.logger(f"Error parsing directory listing JSON: {e}")
        except Exception as e:
            # Generic error handling
            self.preview_text.insert(tk.END, f"Error displaying directory listing: {e}\n\n{listing_result}")
            self.logger(f"Error displaying directory listing: {e}")
    
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
                info["remote_path"],
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
            self.preview_mode.set("raw")
            self.refresh_preview()
            
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
            self.preview_mode.set("raw")
            self.refresh_preview()
            
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