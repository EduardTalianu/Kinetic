import os
import json
import datetime
from core.crypto import KeyManager, CryptoManager
from utils.path_rotation import PathRotationManager

class CampaignManager:
    """Manages campaign settings, configuration, and resources"""
    
    def __init__(self, logger):
        """
        Initialize the campaign manager
        
        Args:
            logger: Function for logging events
        """
        self.logger = logger
        self.active_campaign = None
        self.campaign_config = {}
        self.path_manager = None
        self.crypto_manager = None
        self.key_manager = None
    
    def create_campaign(self, campaign_name, ip, port, beacon_period, kill_date,
                      use_ssl=False, cert_path=None, key_path=None, 
                      url_paths=None, path_rotation=True, rotation_interval=3600):
        """
        Create a new campaign or update an existing one
        
        Args:
            campaign_name: Name of the campaign
            ip: C&C server IP
            port: C&C server port
            beacon_period: Client beacon interval in seconds
            kill_date: Campaign end date (dd/mm/yyyy)
            use_ssl: Whether to use SSL/TLS
            cert_path: Path to SSL certificate (if use_ssl is True)
            key_path: Path to SSL private key (if use_ssl is True)
            url_paths: Custom URL paths
            path_rotation: Whether to enable dynamic path rotation
            rotation_interval: Path rotation interval in seconds
        """
        self.active_campaign = campaign_name
        campaign_folder = campaign_name + "_campaign"
        
        # Create campaign directories
        os.makedirs(campaign_folder, exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "uploads"), exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "agents"), exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "downloads"), exist_ok=True)
        
        # Set up default URL paths if not provided
        if url_paths is None:
            url_paths = {
                "beacon_path": "/beacon",
                "agent_path": "/raw_agent",
                "stager_path": "/b64_stager",
                "cmd_result_path": "/command_result",
                "file_upload_path": "/file_upload"
            }
        
        # Ensure all paths have leading slash
        for key, path in url_paths.items():
            if not path.startswith('/'):
                url_paths[key] = '/' + path
        
        # Save URL paths to file
        url_paths_file = os.path.join(campaign_folder, "url_paths.json")
        try:
            with open(url_paths_file, "w") as f:
                json.dump(url_paths, f, indent=4)
        except Exception as e:
            self.logger(f"Error saving URL paths: {e}")
        
        # Store campaign configuration
        self.campaign_config = {
            "campaign_name": campaign_name,
            "ip": ip,
            "port": port,
            "beacon_period": beacon_period,
            "kill_date": kill_date,
            "use_ssl": use_ssl,
            "cert_path": cert_path,
            "key_path": key_path,
            "url_paths": url_paths,
            "path_rotation": path_rotation,
            "rotation_interval": rotation_interval,
            "created_at": datetime.datetime.now().isoformat()
        }
        
        # Save config to file
        config_content = (
            f"Campaign Name: {campaign_name}\n"
            f"C&C IP: {ip}\n"
            f"Port: {port}\n"
            f"Beacon Period: {beacon_period} sec\n"
            f"Kill Date: {kill_date}\n"
            f"Use SSL: {use_ssl}\n"
            f"Certificate Path: {cert_path if cert_path else ''}\n"
            f"Key Path: {key_path if key_path else ''}\n"
            f"Custom URLs: {bool(url_paths)}\n"
            f"URL Pattern: {'custom'}\n"
            f"Beacon Path: {url_paths['beacon_path']}\n"
            f"Agent Path: {url_paths['agent_path']}\n"
            f"Stager Path: {url_paths['stager_path']}\n"
            f"Command Result Path: {url_paths['cmd_result_path']}\n"
            f"File Upload Path: {url_paths['file_upload_path']}\n"
            f"Path Rotation Enabled: {path_rotation}\n"
            f"Rotation Interval: {rotation_interval} seconds\n"
        )
        
        config_path = os.path.join(campaign_folder, "config.txt")
        try:
            with open(config_path, "w") as f:
                f.write(config_content)
        except Exception as e:
            self.logger(f"Error saving campaign config: {e}")
        
        # Initialize cryptography for this campaign
        self.init_campaign_crypto(campaign_name)
        
        # Initialize path rotation if enabled
        if path_rotation:
            self.init_path_rotation(campaign_folder, url_paths, rotation_interval)
        
        return True
    
    def init_campaign_crypto(self, campaign_name):
        """Initialize cryptography managers for this campaign"""
        campaign_folder = campaign_name + "_campaign"
        self.key_manager = KeyManager(campaign_folder)
        self.crypto_manager = CryptoManager(campaign_name)
        self.logger(f"Campaign cryptography initialized for {campaign_name}")
    
    def init_path_rotation(self, campaign_folder, url_paths, rotation_interval):
        """Initialize the path rotation manager"""
        self.path_manager = PathRotationManager(
            campaign_folder,
            self.logger,
            initial_paths=url_paths,
            rotation_interval=rotation_interval
        )
        self.path_manager.load_state()
        self.logger(f"Path rotation initialized with interval {rotation_interval} seconds")
    
    def load_campaign(self, campaign_folder):
        """
        Load an existing campaign
        
        Args:
            campaign_folder: Path to the campaign folder
        
        Returns:
            Dictionary containing the campaign configuration
        """
        # Get campaign name from folder name
        campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
        
        # Load config.txt
        config_path = os.path.join(campaign_folder, "config.txt")
        if not os.path.exists(config_path):
            self.logger(f"Campaign config not found at {config_path}")
            return None
        
        # Parse config.txt
        with open(config_path, 'r') as f:
            config_lines = f.readlines()
        
        config = {}
        for line in config_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()
        
        # Extract basic settings
        self.campaign_config = {
            "campaign_name": campaign_name,
            "ip": config.get("C&C IP", ""),
            "port": config.get("Port", ""),
            "beacon_period": config.get("Beacon Period", "").split(" ")[0],  # Extract number from "X sec"
            "kill_date": config.get("Kill Date", ""),
            "use_ssl": config.get("Use SSL", "").lower() == "true",
            "cert_path": config.get("Certificate Path", ""),
            "key_path": config.get("Key Path", ""),
            "path_rotation": config.get("Path Rotation Enabled", "").lower() == "true",
            "rotation_interval": int(config.get("Rotation Interval", "3600").split(" ")[0])
        }
        
        # Load URL paths
        url_paths_file = os.path.join(campaign_folder, "url_paths.json")
        if os.path.exists(url_paths_file):
            try:
                with open(url_paths_file, 'r') as f:
                    url_paths = json.load(f)
                self.campaign_config["url_paths"] = url_paths
            except Exception as e:
                self.logger(f"Error loading URL paths: {e}")
                self.campaign_config["url_paths"] = {
                    "beacon_path": "/beacon",
                    "agent_path": "/raw_agent",
                    "stager_path": "/b64_stager",
                    "cmd_result_path": "/command_result",
                    "file_upload_path": "/file_upload"
                }
        
        # Set the active campaign
        self.active_campaign = campaign_name
        
        # Initialize cryptography for this campaign
        self.init_campaign_crypto(campaign_name)
        
        # Initialize path rotation if enabled
        if self.campaign_config["path_rotation"]:
            self.init_path_rotation(
                campaign_folder, 
                self.campaign_config["url_paths"], 
                self.campaign_config["rotation_interval"]
            )
        
        self.logger(f"Campaign {campaign_name} loaded successfully")
        return self.campaign_config
    
    def get_active_campaign(self):
        """Get the name of the active campaign"""
        return self.active_campaign
    
    def get_campaign_config(self):
        """Get the configuration of the active campaign"""
        return self.campaign_config
    
    def get_crypto_manager(self):
        """Get the cryptography manager for the active campaign"""
        return self.crypto_manager
    
    def get_key_manager(self):
        """Get the key manager for the active campaign"""
        return self.key_manager
    
    def get_path_manager(self):
        """Get the path rotation manager for the active campaign"""
        return self.path_manager