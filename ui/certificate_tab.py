import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import socket
import ipaddress
import json
from utils.certificate_generator import generate_certificate, read_certificate_info

class CertificateManagementTab:
    def __init__(self, parent, logger, campaign_tab=None):
        self.frame = ttk.Frame(parent)
        self.logger = logger
        self.campaign_tab = campaign_tab  # Reference to campaign tab to access campaign info
        self.create_widgets()
        
    def create_widgets(self):
        # Main layout - split into left and right panes
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left pane - Certificate generation
        generation_frame = ttk.LabelFrame(main_frame, text="Generate New Certificate")
        generation_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right pane - Certificate information
        info_frame = ttk.LabelFrame(main_frame, text="Certificate Information")
        info_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ===== CERTIFICATE GENERATION =====
        # Certificate Settings
        settings_frame = ttk.Frame(generation_frame)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Certificate output folder
        ttk.Label(settings_frame, text="Output Folder:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.output_var = tk.StringVar()
        self.entry_output = ttk.Entry(settings_frame, textvariable=self.output_var, width=30)
        self.entry_output.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(settings_frame, text="Browse", command=self.browse_output).grid(row=0, column=2, padx=5, pady=5)
        
        # Certificate hostname
        ttk.Label(settings_frame, text="Hostname:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.hostname_var = tk.StringVar(value="localhost")
        self.entry_hostname = ttk.Entry(settings_frame, textvariable=self.hostname_var, width=30)
        self.entry_hostname.grid(row=1, column=1, padx=5, pady=5)
        
        # IP Address
        ttk.Label(settings_frame, text="IP Address:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar()
        self.ip_combo = ttk.Combobox(settings_frame, textvariable=self.ip_var, width=27)
        self.ip_combo.grid(row=2, column=1, padx=5, pady=5)
        self.populate_ip_dropdown()
        
        # Validity period
        ttk.Label(settings_frame, text="Validity (days):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.validity_var = tk.StringVar(value="365")
        validity_values = ["30", "90", "180", "365", "730", "1095"]
        self.validity_combo = ttk.Combobox(settings_frame, textvariable=self.validity_var, 
                                          values=validity_values, width=27)
        self.validity_combo.grid(row=3, column=1, padx=5, pady=5)
        
        # Advanced options expander
        advanced_frame = ttk.LabelFrame(generation_frame, text="Advanced Options")
        advanced_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Organization name
        ttk.Label(advanced_frame, text="Organization:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.org_var = tk.StringVar(value="KCM Testing")
        self.entry_org = ttk.Entry(advanced_frame, textvariable=self.org_var, width=30)
        self.entry_org.grid(row=0, column=1, padx=5, pady=5)
        
        # Country
        ttk.Label(advanced_frame, text="Country:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.country_var = tk.StringVar(value="US")
        self.entry_country = ttk.Entry(advanced_frame, textvariable=self.country_var, width=30)
        self.entry_country.grid(row=1, column=1, padx=5, pady=5)
        
        # State/Province
        ttk.Label(advanced_frame, text="State/Province:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.state_var = tk.StringVar(value="CA")
        self.entry_state = ttk.Entry(advanced_frame, textvariable=self.state_var, width=30)
        self.entry_state.grid(row=2, column=1, padx=5, pady=5)
        
        # Locality/City
        ttk.Label(advanced_frame, text="Locality/City:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.locality_var = tk.StringVar(value="San Francisco")
        self.entry_locality = ttk.Entry(advanced_frame, textvariable=self.locality_var, width=30)
        self.entry_locality.grid(row=3, column=1, padx=5, pady=5)
        
        # Actions buttons
        actions_frame = ttk.Frame(generation_frame)
        actions_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # Generate Certificate Button
        self.btn_generate = ttk.Button(actions_frame, text="Generate Certificate", command=self.generate_certificate)
        self.btn_generate.pack(side=tk.LEFT, padx=5)
        
        # Use in Campaign Button
        self.btn_use_in_campaign = ttk.Button(actions_frame, text="Use in Campaign", command=self.use_in_campaign)
        self.btn_use_in_campaign.pack(side=tk.LEFT, padx=5)
        
        # ===== CERTIFICATE INFORMATION =====
        # Certificate Info Panel
        self.info_text = tk.Text(info_frame, height=20, width=50, wrap=tk.WORD)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.info_text.config(state=tk.DISABLED)
        
        # Info panel actions
        info_actions_frame = ttk.Frame(info_frame)
        info_actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Load Certificate Button
        self.btn_load_cert = ttk.Button(info_actions_frame, text="Load Certificate", command=self.load_certificate)
        self.btn_load_cert.pack(side=tk.LEFT, padx=5)
        
        # Show the default info text
        self.show_default_info()
    
    def show_default_info(self):
        """Show default information in the info panel"""
        info_text = """
Certificate Information Panel

This panel displays information about SSL/TLS certificates.

You can:
1. Generate a new self-signed certificate
2. Load an existing certificate to view its details
3. Use the generated certificate in your campaign

Generated certificates are automatically saved to the specified output folder.
        """
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, info_text)
        self.info_text.config(state=tk.DISABLED)
    
    def populate_ip_dropdown(self):
        """Populate the IP dropdown with available IP addresses"""
        host_ips = self.get_host_ips()
        self.ip_combo['values'] = host_ips
        
        # Set the first IP as default if available
        if host_ips:
            self.ip_var.set(host_ips[0])
    
    def get_host_ips(self):
        """Get host machine IP addresses"""
        host_name = socket.gethostname()
        try:
            host_ips = socket.gethostbyname_ex(host_name)[2]
            # Make sure we include localhost
            if "127.0.0.1" not in host_ips:
                host_ips.append("127.0.0.1")
        except socket.gaierror:
            host_ips = ["127.0.0.1"]
        return host_ips
    
    def browse_output(self):
        """Browse for output directory"""
        # If campaign_tab is available, pre-select the campaign folder
        initial_dir = "."
        if self.campaign_tab:
            campaign_name = self.campaign_tab.entry_campaign.get().strip()
            if campaign_name:
                campaign_dir = f"{campaign_name}_campaign"
                if os.path.exists(campaign_dir):
                    initial_dir = campaign_dir
        
        # Open directory selection dialog
        directory = filedialog.askdirectory(initialdir=initial_dir, title="Select Output Directory")
        if directory:
            self.output_var.set(directory)
            
            # If this is a campaign folder, suggest creating an ssl subfolder
            if directory.endswith("_campaign"):
                ssl_dir = os.path.join(directory, "ssl")
                if not os.path.exists(ssl_dir):
                    os.makedirs(ssl_dir, exist_ok=True)
                self.output_var.set(ssl_dir)
    
    def generate_certificate(self):
        """Generate a new certificate with the specified parameters"""
        # Get values from UI
        output_dir = self.output_var.get().strip()
        hostname = self.hostname_var.get().strip()
        ip_address = self.ip_var.get().strip()
        validity_days = int(self.validity_var.get().strip())
        
        # Get advanced options
        org_name = self.org_var.get().strip()
        country = self.country_var.get().strip()
        state = self.state_var.get().strip()
        locality = self.locality_var.get().strip()
        
        # Validate inputs
        if not output_dir:
            messagebox.showerror("Error", "Please specify an output directory.")
            return
            
        if not hostname and not ip_address:
            messagebox.showerror("Error", "Please specify at least one of hostname or IP address.")
            return
            
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate certificate
            cert_path, key_path = generate_certificate(
                output_dir, 
                hostname, 
                ip_address, 
                validity_days,
                org_name,
                country,
                state,
                locality
            )
            
            # Log success
            self.logger(f"SSL certificate generated successfully: {cert_path}")
            
            # Show success message
            messagebox.showinfo("Success", 
                             f"Certificate generated successfully!\n\n"
                             f"Certificate: {cert_path}\n"
                             f"Private Key: {key_path}\n\n"
                             f"Valid for {validity_days} days.")
            
            # Show certificate information
            self.show_certificate_info(cert_path)
            
        except Exception as e:
            self.logger(f"Error generating certificate: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate certificate: {str(e)}")
    
    def load_certificate(self):
        """Load an existing certificate to view its details"""
        cert_file = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=[("Certificate Files", "*.crt *.pem *.cer"), ("All Files", "*.*")]
        )
        
        if cert_file:
            self.show_certificate_info(cert_file)
    
    def show_certificate_info(self, cert_path):
        """Display certificate information in the info panel"""
        cert_info = read_certificate_info(cert_path)
        
        if "error" in cert_info:
            messagebox.showerror("Error", cert_info["error"])
            return
        
        # Format the certificate information
        info_text = f"Certificate Information for:\n{cert_path}\n\n"
        
        # Subject information
        info_text += "Subject:\n"
        subject = cert_info.get("subject", {})
        for key, value in subject.items():
            info_text += f"  {key}: {value}\n"
        
        # DNS names
        dns_names = cert_info.get("dns_names", [])
        if dns_names:
            info_text += "\nDNS Names:\n"
            for name in dns_names:
                info_text += f"  {name}\n"
                
        # IP addresses
        ip_addresses = cert_info.get("ip_addresses", [])
        if ip_addresses:
            info_text += "\nIP Addresses:\n"
            for ip in ip_addresses:
                info_text += f"  {ip}\n"
                
        # Validity period
        info_text += f"\nValid From: {cert_info.get('not_valid_before', 'Unknown')}\n"
        info_text += f"Valid Until: {cert_info.get('not_valid_after', 'Unknown')}\n"
        info_text += f"Days Remaining: {cert_info.get('days_remaining', 'Unknown')}\n"
        
        # Issuer information (for self-signed certs, same as subject)
        info_text += "\nIssuer:\n"
        issuer = cert_info.get("issuer", {})
        for key, value in issuer.items():
            info_text += f"  {key}: {value}\n"
            
        # Display the information
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, info_text)
        self.info_text.config(state=tk.DISABLED)
        
        # Store the paths for use in campaign
        self.current_cert_path = cert_path
        key_path = os.path.splitext(cert_path)[0] + ".key"
        self.current_key_path = key_path if os.path.exists(key_path) else None
    
    def use_in_campaign(self):
        """Use the current certificate in the campaign configuration"""
        if not hasattr(self, 'current_cert_path') or not self.current_cert_path:
            messagebox.showerror("Error", "No certificate is currently loaded.")
            return
            
        if not hasattr(self, 'current_key_path') or not self.current_key_path:
            messagebox.showerror("Error", "Cannot find the key file for this certificate.")
            return
            
        if not self.campaign_tab:
            messagebox.showerror("Error", "No campaign tab available.")
            return
            
        # Set the certificate and key paths in the campaign tab
        self.campaign_tab.ssl_var.set(True)
        self.campaign_tab.toggle_ssl_options()  # Enable SSL fields
        
        self.campaign_tab.entry_cert.delete(0, tk.END)
        self.campaign_tab.entry_cert.insert(0, self.current_cert_path)
        
        self.campaign_tab.entry_key.delete(0, tk.END)
        self.campaign_tab.entry_key.insert(0, self.current_key_path)
        
        # Log and notify
        self.logger(f"Certificate {self.current_cert_path} set for use in campaign")
        messagebox.showinfo("Success", "Certificate has been set for use in the campaign.")