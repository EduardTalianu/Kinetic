import datetime
import logging
import subprocess
import threading
import platform
import time

# Configure logging for command execution
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CommandExecutor:
    def __init__(self, client_manager):
        self.client_manager = client_manager
        self.running = True
        self.thread = threading.Thread(target=self.process_commands, daemon=True)
        self.thread.start()

    def process_commands(self):
        """Background thread to process pending commands for all clients."""
        while self.running:
            for client_id, info in self.client_manager.get_clients_info().items():
                pending_commands = info.get("pending_commands", [])
                if pending_commands:
                    command = pending_commands[0]  # Process the first command in the queue
                    self.execute_command(client_id, command)
                    # Remove only the executed command from pending
                    if client_id in self.client_manager.clients:
                        self.client_manager.clients[client_id]["pending_commands"].pop(0)
            time.sleep(1)  # Sleep for 1 second between checks

    def execute_command(self, client_id, command):
        """Execute the command and log the result."""
        timestamp = command["timestamp"]
        command_type = command["command_type"]
        args = command["args"]

        logger.info(f"Executing command for client {client_id}: {command_type} {args}")

        try:
            if command_type == "execute":
                result = self.run_system_command(args)
                logger.info(f"Command result for {client_id}: {result}")
                self.update_history(client_id, command, result)
            elif command_type == "upload":
                # Placeholder for upload logic (not implemented here)
                result = f"Upload command '{args}' not implemented yet"
                logger.info(f"Command result for {client_id}: {result}")
                self.update_history(client_id, command, result)
            else:
                logger.warning(f"Unknown command type '{command_type}' for client {client_id}")
                self.update_history(client_id, command, f"Unknown command type: {command_type}")
        except Exception as e:
            logger.error(f"Error executing command for {client_id}: {str(e)}")
            self.update_history(client_id, command, f"Error: {str(e)}")

    def run_system_command(self, args):
        """Execute a real system command and return its output."""
        try:
            # Detect the operating system
            is_windows = platform.system() == "Windows"

            # Adjust command for platform compatibility
            if args == "whoami" and not is_windows:
                args = "id -un"  # Use 'id -un' on Unix-like systems instead of 'whoami'

            # Run the command and capture output
            result = subprocess.run(
                args.split(),  # Split args into list for subprocess (assumes space-separated args)
                shell=is_windows,  # Use shell=True on Windows for built-in commands like 'dir'
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()  # Return the command output
        except subprocess.CalledProcessError as e:
            return f"Command failed with error: {e.stderr.strip()}"
        except Exception as e:
            return f"Execution error: {str(e)}"

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
                    
            # Update pending commands with result
            for cmd in self.client_manager.clients[client_id]["pending_commands"]:
                if cmd["timestamp"] == command["timestamp"]:
                    cmd["result"] = result
                    break
            
            # Log the command and result
            self.client_manager.log_event(client_id, "Command Result", 
                f"Command: {command['command_type']} {command['args']} | Result: {result}")

            # Notify the ClientManager that a command result has been updated
            self.client_manager.on_command_updated(client_id)

    def stop(self):
        """Stop the command processing thread."""
        self.running = False
        self.thread.join()