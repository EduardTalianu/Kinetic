import os
import importlib.util
import logging

logger = logging.getLogger(__name__)

class CommandLoader:
    """Handles loading command modules from the commands directory"""
    
    def __init__(self):
        """Initialize the command loader"""
        self.commands = {
            'host': {},
            'network': {},
            'activedirectory': {},
            'scripts': {},
            'system': {}
        }
        
        # Root directory of the application
        self.app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.cmd_dir = os.path.join(self.app_root, 'commands')
        
        # Load all commands
        self.load_commands()
    
    def load_commands(self):
        """Load all command modules from the commands directory"""
        # Check if commands directory exists
        if not os.path.exists(self.cmd_dir):
            os.makedirs(self.cmd_dir, exist_ok=True)
            # Create category directories
            for category in self.commands.keys():
                os.makedirs(os.path.join(self.cmd_dir, category), exist_ok=True)
            logger.warning(f"Command directory structure created at {self.cmd_dir}")
            print(f"Command directory structure created at {self.cmd_dir}")
            return
        
        # Load commands from each category directory
        for category in self.commands.keys():
            category_dir = os.path.join(self.cmd_dir, category)
            
            # Create category directory if it doesn't exist
            if not os.path.exists(category_dir):
                os.makedirs(category_dir, exist_ok=True)
                print(f"Created missing category directory: {category_dir}")
                continue
            
            # Print the contents of the category directory for debugging
            print(f"Checking {category_dir} for commands...")
            if os.path.exists(category_dir):
                print(f"Files in {category_dir}: {os.listdir(category_dir)}")
            else:
                print(f"Directory does not exist: {category_dir}")
                
            # Load Python modules from this directory
            for filename in os.listdir(category_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]  # Remove .py extension
                    module_path = os.path.join(category_dir, filename)
                    
                    try:
                        # Load the module dynamically
                        spec = importlib.util.spec_from_file_location(f"commands.{category}.{module_name}", module_path)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Verify module has required functions
                        if hasattr(module, 'execute') and callable(module.execute):
                            description = ""
                            if hasattr(module, 'get_description') and callable(module.get_description):
                                description = module.get_description()
                                
                            # Get tags if available, otherwise use defaults
                            tags = {}
                            if hasattr(module, 'get_tags') and callable(module.get_tags):
                                tags = module.get_tags()
                            else:
                                tags = self._get_default_tags(module_name, category)
                                
                            # Add command to the appropriate category
                            self.commands[category][module_name] = {
                                'module': module,
                                'description': description,
                                'tags': tags
                            }
                            print(f"Loaded command module: {category}/{module_name}")
                        else:
                            print(f"Module {module_name} missing required 'execute' function")
                    except Exception as e:
                        print(f"Error loading module {module_name}: {e}")
                        import traceback
                        traceback.print_exc()
        
        # Log summary of loaded commands
        total_commands = sum(len(cmds) for cmds in self.commands.values())
        logger.info(f"Loaded {total_commands} command modules from {len(self.commands)} categories")
        print(f"Loaded {total_commands} command modules from {len(self.commands)} categories")
    
    def _get_default_tags(self, module_name, category):
        """Generate default tags based on module name and category"""
        # Some simple heuristics based on command name and category
        is_powershell = "_ps" in module_name
        is_cmd = not is_powershell
        is_admin = any(word in module_name for word in ["admin", "registry", "service", "driver", "priv"])
        
        # Special case for whoami and whoami_ps
        if module_name == "whoami":
            return {
                "opsec_safe": True,
                "requires_admin": False,
                "windows": True,
                "linux": True,
                "powershell": False,
                "cmd": True
            }
        elif module_name == "whoami_ps":
            return {
                "opsec_safe": True,
                "requires_admin": False,
                "windows": True,
                "linux": False,
                "powershell": True,
                "cmd": False
            }
        
        # Default tags based on category and module name
        return {
            "opsec_safe": not is_admin,
            "requires_admin": is_admin,
            "windows": True,
            "linux": category != "activedirectory" and not is_powershell,
            "powershell": is_powershell,
            "cmd": is_cmd
        }
    
    def get_categories(self):
        """Get a list of all command categories"""
        # Return only categories that have commands
        return [cat for cat in self.commands.keys() if self.commands[cat]]
    
    def get_commands(self, category):
        """Get all commands in a category"""
        return self.commands.get(category, {})
    
    def execute_command(self, category, command_name, client_interaction_ui, client_id):
        """Execute a command by category and name"""
        if category in self.commands and command_name in self.commands[category]:
            command = self.commands[category][command_name]
            try:
                command['module'].execute(client_interaction_ui, client_id)
                return True
            except Exception as e:
                logger.error(f"Error executing command {category}/{command_name}: {e}")
                return False
        logger.warning(f"Command not found: {category}/{command_name}")
        return False