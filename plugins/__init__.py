"""
Plugin system for Kinetic Compliance Matrix

This package contains the plugin interface, plugin manager, and default plugins
for agent generation.
"""

import os
import sys
import logging

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
        
        # Get the plugin manager instance
        plugin_manager = get_plugin_manager()
        
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