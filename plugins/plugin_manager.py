import os
import sys
import inspect
import importlib.util
import logging
from typing import Dict, List, Type, Optional

from plugins.agent_plugin_interface import AgentPluginInterface

# Configure logging
logger = logging.getLogger(__name__)


class PluginManager:
    """
    Manager for agent generation plugins
    Handles discovery, loading, and access to plugins
    """
    
    def __init__(self, plugins_dir: Optional[str] = None):
        """
        Initialize the plugin manager
        
        Args:
            plugins_dir: Directory containing plugin modules, defaults to 'plugins/agent_plugins'
        """
        self.plugins_dir = plugins_dir or os.path.join(os.path.dirname(__file__), "agent_plugins")
        self._plugins: Dict[str, Type[AgentPluginInterface]] = {}
        self._loaded = False
    
    def discover_plugins(self) -> None:
        """
        Discover and load all available plugins from the plugins directory
        """
        if not os.path.exists(self.plugins_dir):
            logger.warning(f"Plugins directory does not exist: {self.plugins_dir}")
            os.makedirs(self.plugins_dir, exist_ok=True)
            return
        
        # Find all Python files in the plugins directory
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_path = os.path.join(self.plugins_dir, filename)
                module_name = filename[:-3]  # Remove .py extension
                
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
                                
                                try:
                                    # Register the plugin
                                    plugin_name = obj.get_name()
                                    self._plugins[plugin_name] = obj
                                    logger.info(f"Loaded plugin: {plugin_name} from {filename}")
                                except Exception as e:
                                    logger.error(f"Error registering plugin from {filename}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error loading plugin module {module_name}: {str(e)}")
        
        self._loaded = True
        logger.info(f"Discovered {len(self._plugins)} plugins")
    
    def register_plugin(self, plugin_class: Type[AgentPluginInterface]) -> None:
        """
        Manually register a plugin class
        
        Args:
            plugin_class: A class implementing AgentPluginInterface
        """
        if not issubclass(plugin_class, AgentPluginInterface):
            raise TypeError("Plugin class must implement AgentPluginInterface")
        
        plugin_name = plugin_class.get_name()
        self._plugins[plugin_name] = plugin_class
        logger.info(f"Manually registered plugin: {plugin_name}")
    
    def get_plugin(self, name: str) -> Optional[Type[AgentPluginInterface]]:
        """
        Get a specific plugin by name
        
        Args:
            name: Name of the plugin to retrieve
            
        Returns:
            The plugin class, or None if not found
        """
        if not self._loaded:
            self.discover_plugins()
        
        return self._plugins.get(name)
    
    def get_all_plugins(self) -> Dict[str, Type[AgentPluginInterface]]:
        """
        Get all available plugins
        
        Returns:
            Dictionary mapping plugin names to plugin classes
        """
        if not self._loaded:
            self.discover_plugins()
        
        return self._plugins.copy()
    
    def get_plugin_names(self) -> List[str]:
        """
        Get names of all available plugins
        
        Returns:
            List of plugin names
        """
        if not self._loaded:
            self.discover_plugins()
        
        return list(self._plugins.keys())
    
    def get_plugins_by_platform(self, platform: str) -> Dict[str, Type[AgentPluginInterface]]:
        """
        Get plugins that support a specific platform
        
        Args:
            platform: Platform name (e.g., "windows", "linux", "macos")
            
        Returns:
            Dictionary mapping plugin names to plugin classes
        """
        if not self._loaded:
            self.discover_plugins()
        
        return {
            name: plugin_class 
            for name, plugin_class in self._plugins.items()
            if platform in plugin_class.get_supported_platforms()
        }
    
    def get_plugins_by_capability(self, capability: str) -> Dict[str, Type[AgentPluginInterface]]:
        """
        Get plugins that support a specific capability
        
        Args:
            capability: Capability name (e.g., "file_operations", "screenshot")
            
        Returns:
            Dictionary mapping plugin names to plugin classes
        """
        if not self._loaded:
            self.discover_plugins()
        
        return {
            name: plugin_class 
            for name, plugin_class in self._plugins.items()
            if capability in plugin_class.get_agent_capabilities()
        }


# Singleton instance of the plugin manager
_plugin_manager = None


def get_plugin_manager() -> PluginManager:
    """
    Get the singleton instance of the plugin manager
    
    Returns:
        PluginManager instance
    """
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    
    return _plugin_manager