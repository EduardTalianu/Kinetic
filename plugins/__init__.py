"""
Plugin system for Kinetic Compliance Matrix

This package contains the plugin interface, plugin manager, and default plugins
for agent generation.
"""

import os
import sys
import logging
import importlib.util
import inspect

# Configure logging
logger = logging.getLogger(__name__)

def initialize_plugin_system():
    """
    Initialize the plugin system by loading all available plugins
    
    Returns:
        bool: True if initialization was successful, False otherwise
    """
    # Import the plugin manager
    try:
        from plugins.plugin_manager import get_plugin_manager
        from plugins.agent_plugin_interface import AgentPluginInterface
        
        # Get the plugin manager instance
        plugin_manager = get_plugin_manager()
        
        # Discover plugins automatically
        plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_plugins")
        
        # Log the plugins directory being searched
        logger.info(f"Searching for plugins in: {plugins_dir}")
        
        if os.path.exists(plugins_dir):
            # Find all Python files in the plugins directory
            for filename in os.listdir(plugins_dir):
                if filename.endswith(".py") and not filename.startswith("__"):
                    module_path = os.path.join(plugins_dir, filename)
                    module_name = f"plugins.agent_plugins.{filename[:-3]}"
                    
                    try:
                        # Dynamically load the module
                        spec = importlib.util.spec_from_file_location(module_name, module_path)
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            
                            # Find all classes that implement AgentPluginInterface
                            for name, obj in inspect.getmembers(module):
                                if (inspect.isclass(obj) and 
                                    obj is not AgentPluginInterface and 
                                    issubclass(obj, AgentPluginInterface)):
                                    
                                    # Register the plugin
                                    plugin_manager.register_plugin(obj)
                                    logger.info(f"Auto-registered plugin: {obj.get_name()} from {filename}")
                    except Exception as e:
                        logger.error(f"Error loading plugin module {module_name}: {str(e)}")
        else:
            logger.warning(f"Plugins directory does not exist: {plugins_dir}")
        
        # Discover all available plugins
        plugin_manager.discover_plugins()
        
        # Log the discovered plugins
        plugins = plugin_manager.get_all_plugins()
        logger.info(f"Initialized plugin system with {len(plugins)} plugins")
        for name in plugin_manager.get_plugin_names():
            logger.info(f"  - {name}")
        
        return True
    except Exception as e:
        logger.error(f"Error initializing plugin system: {e}")
        return False


# Create plugins directory structure if it doesn't exist
def ensure_plugin_directories():
    """Create the plugin directory structure if it doesn't exist"""
    # Get the root directory of the application
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Create plugins directory
    plugins_dir = os.path.join(root_dir, "plugins")
    os.makedirs(plugins_dir, exist_ok=True)
    
    # Create agent_plugins directory
    agent_plugins_dir = os.path.join(plugins_dir, "agent_plugins")
    os.makedirs(agent_plugins_dir, exist_ok=True)
    
    logger.info(f"Plugin directories created/verified: {plugins_dir}, {agent_plugins_dir}")