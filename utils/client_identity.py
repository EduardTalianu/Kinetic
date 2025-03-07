import os
import json
import hashlib
import datetime

class ClientVerifier:
    """Handles verification of client identity across sessions"""
    
    def __init__(self, campaign_folder):
        self.campaign_folder = campaign_folder
        self.clients_file = os.path.join(campaign_folder, "known_clients.json")
        self.known_clients = self._load_known_clients()
        
    def _load_known_clients(self):
        """Load the known clients from file"""
        if os.path.exists(self.clients_file):
            try:
                with open(self.clients_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading known clients: {e}")
                return {}
        return {}
    
    def _save_known_clients(self):
        """Save the known clients to file"""
        os.makedirs(os.path.dirname(self.clients_file), exist_ok=True)
        with open(self.clients_file, 'w') as f:
            json.dump(self.known_clients, f, indent=2)
    
    def register_client(self, client_id, system_info):
        """Register a new client or update an existing one"""
        if client_id not in self.known_clients:
            self.known_clients[client_id] = {
                "first_seen": datetime.datetime.now().isoformat(),
                "system_info": system_info,
                "ip_history": [system_info.get("ip", "Unknown")],
                "hostname_history": [system_info.get("hostname", "Unknown")]
            }
        else:
            # Update existing client
            client = self.known_clients[client_id]
            
            # Update IP history if it's new
            current_ip = system_info.get("ip", "Unknown")
            if current_ip not in client["ip_history"]:
                client["ip_history"].append(current_ip)
            
            # Update hostname history if it's new
            current_hostname = system_info.get("hostname", "Unknown")
            if current_hostname not in client["hostname_history"]:
                client["hostname_history"].append(current_hostname)
            
            # Update system info with any new values
            client["system_info"].update(system_info)
            
            # Update last seen
            client["last_seen"] = datetime.datetime.now().isoformat()
            
        self._save_known_clients()
        
    def verify_client(self, client_id, system_info):
        """
        Verify if a client is who they claim to be
        Returns (is_verified, confidence_level, warnings)
        """
        if client_id not in self.known_clients:
            return False, 0, ["Unknown client"]
        
        known_info = self.known_clients[client_id]["system_info"]
        warnings = []
        points = 0
        max_points = 0
        
        # Check critical identifiers
        if known_info.get("MachineGuid") != system_info.get("MachineGuid"):
            warnings.append("Machine GUID mismatch")
            points -= 50  # Major red flag
        else:
            points += 30
        max_points += 30
        
        # Check hostname
        if known_info.get("Hostname") != system_info.get("Hostname"):
            warnings.append("Hostname changed")
            # Check if it's in history
            if system_info.get("Hostname") in self.known_clients[client_id]["hostname_history"]:
                points += 5  # Less concerning if we've seen this hostname before
            else:
                points -= 10
        else:
            points += 15
        max_points += 15
        
        # Check username
        if known_info.get("Username") != system_info.get("Username"):
            warnings.append("Username changed")
            points -= 10
        else:
            points += 15
        max_points += 15
        
        # Check MAC address
        if known_info.get("MacAddress") != system_info.get("MacAddress"):
            warnings.append("MAC address changed")
            points -= 20
        else:
            points += 20
        max_points += 20
        
        # Check OS version
        if known_info.get("OsVersion") != system_info.get("OsVersion"):
            warnings.append("OS version changed")
            points -= 5
        else:
            points += 10
        max_points += 10
        
        # Check domain
        if known_info.get("Domain") != system_info.get("Domain"):
            warnings.append("Domain changed")
            points -= 10
        else:
            points += 10
        max_points += 10
        
        # Calculate confidence level (0-100%)
        confidence = (points / max_points) * 100 if max_points > 0 else 0
        confidence = max(0, min(100, confidence))  # Clamp between 0 and 100
        
        is_verified = confidence >= 70  # Threshold for verification
        
        return is_verified, confidence, warnings


def generate_client_id(ip, hostname, username, machine_guid, os_version):
    """Generate a unique client ID from system information - always use the JPEG format"""
    # Prioritize machine_guid if available as it's the most stable identifier
    if machine_guid and machine_guid != "Unknown":
        # Create a hash from the machine GUID
        hash_bytes = hashlib.sha256(machine_guid.encode()).hexdigest()[:5].upper()
        # Format as XXXXX-img.jpeg to look like an image file
        return f"{hash_bytes}-img.jpeg"
    
    # Otherwise use a combination of identifiers
    # Create a combined string of identifying information - exclude IP as it might change
    identifier = f"{hostname}|{username}|{os_version}"
    
    # Hash it to create a stable, unique identifier
    hash_str = hashlib.sha256(identifier.encode()).hexdigest()[:5].upper()
    
    # Format as XXXXX-img.jpeg to look like an image file
    return f"{hash_str}-img.jpeg"


def extract_system_info(system_info_json):
    """
    Extract key system properties from system info JSON
    Returns a tuple of (hostname, username, machine_guid, os_version, mac_address, system_info)
    """
    try:
        system_info = json.loads(system_info_json) if isinstance(system_info_json, str) else system_info_json
        
        hostname = system_info.get('Hostname', 'Unknown')
        username = system_info.get('Username', 'Unknown')
        machine_guid = system_info.get('MachineGuid', 'Unknown')
        os_version = system_info.get('OsVersion', 'Unknown')
        mac_address = system_info.get('MacAddress', 'Unknown')
        
        return hostname, username, machine_guid, os_version, mac_address, system_info
    except Exception as e:
        print(f"Error extracting system information: {e}")
        return 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', {}


def get_powershell_system_info_script():
    """Return a PowerShell script that collects comprehensive system information"""
    return """
function Get-SystemIdentification {
    # Gather system identification information
    $systemInfo = @{
        Hostname = [System.Net.Dns]::GetHostName()
        Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OsVersion = [System.Environment]::OSVersion.VersionString
        Architecture = if ([System.Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
        ProcessorCount = [System.Environment]::ProcessorCount
        TotalMemory = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    }
    
    # Get Machine GUID - this is a relatively stable identifier
    try {
        $machineGuid = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name "MachineGuid" -ErrorAction Stop).MachineGuid
        $systemInfo.MachineGuid = $machineGuid
    } catch {
        $systemInfo.MachineGuid = "Unknown"
    }
    
    # Get MAC address of first network adapter
    try {
        $networkAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null } | Select-Object -First 1
        $systemInfo.MacAddress = $networkAdapter.MACAddress
    } catch {
        $systemInfo.MacAddress = "Unknown"
    }
    
    # Get installed security products
    try {
        $antivirusProducts = Get-WmiObject -Namespace "root\\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }
        $systemInfo.SecurityProducts = $antivirusProducts -join ", "
    } catch {
        $systemInfo.SecurityProducts = "Unknown"
    }
    
    # Get domain information
    try {
        $computerSystem = Get-WmiObject Win32_ComputerSystem
        $systemInfo.Domain = $computerSystem.Domain
        $systemInfo.PartOfDomain = $computerSystem.PartOfDomain
    } catch {
        $systemInfo.Domain = "Unknown"
        $systemInfo.PartOfDomain = $false
    }
    
    # Get public IP (if accessible)
    try {
        $publicIp = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content
        $systemInfo.PublicIp = $publicIp
    } catch {
        $systemInfo.PublicIp = "Unknown"
    }
    
    # Get hardware information
    try {
        $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
        $systemInfo.CpuName = $cpu.Name
        $systemInfo.CpuId = $cpu.ProcessorId
    } catch {
        $systemInfo.CpuName = "Unknown"
        $systemInfo.CpuId = "Unknown"
    }
    
    # Get BIOS information
    try {
        $bios = Get-WmiObject Win32_BIOS
        $systemInfo.BiosSerial = $bios.SerialNumber
        $systemInfo.BiosVersion = $bios.Version
    } catch {
        $systemInfo.BiosSerial = "Unknown"
        $systemInfo.BiosVersion = "Unknown"
    }
    
    # Get disk information
    try {
        $disks = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            @{
                Drive = $_.DeviceID
                Size = [math]::Round($_.Size / 1GB, 2)
                FreeSpace = [math]::Round($_.FreeSpace / 1GB, 2)
            }
        }
        $systemInfo.Disks = $disks
    } catch {
        $systemInfo.Disks = @()
    }
    
    # Convert to JSON
    $jsonInfo = ConvertTo-Json -InputObject $systemInfo -Compress
    return $jsonInfo
}

# Call the function
Get-SystemIdentification
"""