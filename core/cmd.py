import datetime
import logging
import threading
import time

# Configure logging for command execution
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CommandExecutor:
    def __init__(self, client_manager):
        self.client_manager = client_manager
        self.running = True
        # Start background thread to monitor command status - doesn't execute commands locally
        self.thread = threading.Thread(target=self.monitor_command_status, daemon=True)
        self.thread.start()

    def monitor_command_status(self):
        """Background thread to monitor command status - doesn't execute commands locally"""
        while self.running:
            # Just update command status based on communication with real clients
            for client_id, info in self.client_manager.get_clients_info().items():
                pending_commands = info.get("pending_commands", [])
                # Log number of pending commands
                if pending_commands:
                    logger.debug(f"Client {client_id} has {len(pending_commands)} pending commands")
            time.sleep(5)  # Check every 5 seconds

    def add_command(self, client_id, command_type, args):
        """Add a command to the client's queue - no local execution"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create command object
        command = {
            "timestamp": timestamp,
            "command_type": command_type,
            "args": args
        }
        
        # Add to client's pending commands
        self.client_manager.add_command(client_id, command_type, args)
        logger.info(f"Command queued for client {client_id}: {command_type} {args}")
        
        return command

    def update_history(self, client_id, command, result):
        """Update client history with execution result."""
        updated_command = command.copy()
        updated_command["result"] = result
        updated_command["executed_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if client_id in self.client_manager.clients:
            # Replace the executed command in history with the updated version
            for i, cmd in enumerate(self.client_manager.clients[client_id]["history"]):
                if cmd["timestamp"] == command["timestamp"]:
                    self.client_manager.clients[client_id]["history"][i] = updated_command
                    break
            
            # Log the command and result
            self.client_manager.log_event(client_id, "Command Result", 
                f"Command: {command['command_type']} {command['args']} | Result: {result}")

            # Notify the ClientManager that a command result has been updated
            self.client_manager.on_command_updated(client_id)

    def execute_command(self, client_id, command):
        """Handle command processing and update status - doesn't execute locally"""
        timestamp = command["timestamp"]
        command_type = command["command_type"]
        args = command["args"]

        logger.info(f"Processing command for client {client_id}: {command_type} {args}")
        
        # Mark it as sent
        self.update_history(client_id, command, "Command sent to client, waiting for response...")

    def process_commands(self):
        """Background thread to process any pending commands"""
        while self.running:
            for client_id, info in self.client_manager.get_clients_info().items():
                pending_commands = info.get("pending_commands", [])
                if pending_commands:
                    try:
                        command = pending_commands[0]  # Process the first command in the queue
                        self.execute_command(client_id, command)
                    except IndexError:
                        # Handle the case where the list might be empty now
                        logger.warning(f"Pending commands for client {client_id} were cleared during processing")
                    except Exception as e:
                        logger.error(f"Error processing command for client {client_id}: {e}")
            time.sleep(1)  # Sleep for 1 second between checks

    def stop(self):
        """Stop the command processing thread."""
        self.running = False
        self.thread.join()