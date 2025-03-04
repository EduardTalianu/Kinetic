#!/usr/bin/env python3
"""
Kinetic Compliance Matrix - Command and Control Framework

A modular and extensible command and control (C2) framework for security
testing and assessment purposes.
"""

import os
import sys
import tkinter as tk
import argparse
import logging

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.app import MainGUI
from core.config import ConfigManager
from core.logging import LogManager

def setup_logging():
    """Set up basic logging for the application"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure file logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename='logs/main.log',
        filemode='a'
    )
    
    # Add console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    return logging.getLogger('main')

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Kinetic Compliance Matrix - C2 Framework')
    parser.add_argument('--headless', action='store_true', help='Run in headless mode (no GUI)')
    parser.add_argument('--campaign', type=str, help='Campaign name to automatically load')
    parser.add_argument('--config', type=str, help='Path to config file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    return parser.parse_args()

def main():
    """Main application entry point"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging
    logger = setup_logging()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    logger.info("Starting Kinetic Compliance Matrix")
    
    # Load configuration
    config_manager = ConfigManager()
    if args.config:
        # Custom config file specified
        config_manager.config_file = args.config
        config_manager.load_config()
    
    if args.headless:
        # Implement headless mode here
        logger.info("Running in headless mode")
        # This would typically load a campaign and start the C2 server
        # without a GUI, possibly controlled through a REST API or CLI
        print("Headless mode not yet implemented")
        return
    
    # Start the GUI
    root = tk.Tk()
    app = MainGUI(root)
    
    # If a campaign was specified, load it automatically
    if args.campaign:
        logger.info(f"Auto-loading campaign: {args.campaign}")
        # This would call into the app to load the specified campaign
        # Needs to be implemented in the MainGUI class
    
    # Start the main loop
    logger.info("Starting main GUI loop")
    root.mainloop()
    
    logger.info("Exiting Kinetic Compliance Matrix")

if __name__ == "__main__":
    main()