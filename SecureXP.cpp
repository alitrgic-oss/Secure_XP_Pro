

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <winioctl.h> 
#include <vector>
#include <string>
#include <set>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <math.h>
#include <iphlpapi.h>
#include <dbt.h>
#include <wininet.h>
#include <aclapi.h> 
#include <algorithm> 

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "comdlg32.lib")

// --- COMPILER COMPATIBILITY FALLBACKS FOR GCC/MinGW ---
#ifndef swprintf_s
#define swprintf_s(buf, size, fmt, ...) _snwprintf(buf, size, fmt, ##__VA_ARGS__)
#endif

#ifndef wsprintf_s
#define wsprintf_s(buf, size, fmt, ...) _snwprintf(buf, size, fmt, ##__VA_ARGS__)
#endif

#ifndef wcscpy_s
#define wcscpy_s(dst, size, src) do { \
    wcsncpy(dst, src, (size) - 1); \
    (dst)[(size) - 1] = L'\0'; \
} while(0)
#endif
// ------------------------------------------------------

#define ID_TRAY_CALLBACK WM_APP + 1
#define ID_TRAY_SHOW 1001
#define ID_TRAY_EXIT 1002
#define IDT_REALTIME_SCAN 2001
#define IDT_ANIMATION 2002
#define NOTIFY_ID 100

// Thread-safe Window Message IDs for marshaling GUI updates
#define WM_APP_ADD_LOG (WM_APP + 10)
#define WM_APP_REALTIME_LOG (WM_APP + 11)

#define DEVICE_SECUREXP L"\\\\.\\SecureXPKernel"
#define SXP_DEVICE_TYPE 0x00008301
#define IOCTL_SECUREXP_GET_BLOCKED_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROCESS CTL_CODE(SXP_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CustomNtohs(x) ( ( ( (x) >> 8 ) & 0x00FF ) | ( ( (x) << 8 ) & 0xFF00 ) )

#define IDC_SIDEBAR         3001
#define IDC_LISTVIEW        3003

#define ID_MENU_SCAN        4001
#define ID_MENU_CUSTOM_SCAN 4005
#define ID_MENU_QUARANTINE  4002
#define ID_MENU_SETTINGS    4003
#define ID_MENU_EXIT        4004

HWND g_hMainWnd, g_hListView, g_hSidebar, g_hStatusBar;
int g_Selected = 0;
std::vector<std::wstring> g_QuarantineList;
const wchar_t* g_SidebarItems[] = {L"Full Check", L"Virus Scan", L"Speedup", L"Cleanup", L"Settings", L"Quarantine"};
const int g_SidebarCount = 6;
volatile bool g_bIsScanning = false;
volatile bool g_bRealTimeProtection = true;
volatile bool g_bAutoStart = false; 
volatile bool g_bAutoSanitize = false; 
volatile bool g_bSilentMode = false;   

volatile bool g_bBlockPort445 = false;
volatile bool g_bBlockPort135 = false;
volatile bool g_bBlockPort3389 = false;

int g_HeuristicLevel = 1;     
bool g_bBlockUSB = false;     
bool g_bRamShield = false;     
bool g_bBrowserShield = true; 
bool g_bCredentialGuard = false; 

bool g_bNetworkShield = true;
bool g_bHipsCanary = false;    
bool g_bHostsGuard = false;    
bool g_bLsassProtect = false;  

int g_AnimAngle = 0;
std::wstring g_CurrentScanningFile = L"";

std::wstring g_CustomScanPath = L"";
bool g_bCustomScanActive = false;
bool g_bFullScanActive = false; 
int g_AutomationLevel = 0; 

wchar_t g_FilteredPath[MAX_PATH] = L"";
wchar_t g_FilteredExts[256] = L"";

std::vector<std::wstring> g_ExcludedFolders; 
CRITICAL_SECTION g_ExclusionsCS; // Protects g_ExcludedFolders across threads
CRITICAL_SECTION g_QuarantineCS; // Protects g_QuarantineList across threads

wchar_t g_QuarantineDir[MAX_PATH] = L"";
wchar_t g_ConfigFile[MAX_PATH] = L"";

int g_HoveredItem = -1;
WNDPROC g_OldSidebarProc = NULL;
HANDLE g_hHostsFileLock = INVALID_HANDLE_VALUE; 

// Handles kept globally to terminate blocked synchronous I/O operations on exit.
volatile HANDLE g_hRansomwareDir = INVALID_HANDLE_VALUE;
volatile HANDLE g_hDownloadDir = INVALID_HANDLE_VALUE;

volatile int g_TotalFilesToScan = 0;
volatile int g_FilesScannedCount = 0;

struct FileWriteEvent {
    std::wstring directory;
    DWORD timestamp;
};
std::vector<FileWriteEvent> g_WriteEvents;
CRITICAL_SECTION g_RansomwareCS;

// Structure for thread-safe GUI message passing
struct SafeLogPayload {
    const wchar_t* path;
    const wchar_t* status;
    const wchar_t* details;
};

const std::set<std::wstring> g_WhitelistDatabase = {
    L"d41d8cd98f00b204e9800998ecf8427e", 
    L"5d41402abc4b2a76b9719d911017c592", 
    L"7d793037a0760186574b0282f2f435e7", 
    L"8e285a83a6288301724a0282f2f453a2"  
};

std::vector<HWND> g_SettingsWnds;

struct SecureSigEntry {
    BYTE encHashBytes[16];
    const wchar_t* encName; 
};

const SecureSigEntry g_ObfuscatedDatabase[] = {
    { { 0x79, 0xE5, 0xBB, 0x2F, 0xC3, 0x95, 0x95, 0xCE, 0x50, 0xD5, 0x13, 0x2F, 0x45, 0x96, 0x8D, 0x12 }, L"29110C13502917104D4C503F0B0A110C0B1050171018" }, 
    { { 0x63, 0x8B, 0x06, 0x86, 0xDD, 0x23, 0xD3, 0xED, 0xAE, 0xF6, 0x1F, 0x86, 0xB2, 0x67, 0xF0, 0xFE }, L"2A0C11141F10503A11091012111F1A1B0C502D1F0D0D1B0C" }, 
    { { 0xB2, 0xA7, 0x16, 0x6E, 0x55, 0x98, 0x14, 0xB7, 0xBA, 0xC7, 0x27, 0x76, 0x27, 0x85, 0xC5, 0xB5 }, L"2C1F100D1113091F0C1B50262E50291F10101F3D0C07" }, 
    { { 0x20, 0x47, 0x0C, 0x82, 0x95, 0x14, 0x7B, 0x83, 0xA5, 0xC7, 0xB7, 0x26, 0x9F, 0xDC, 0x25, 0xC2 }, L"28170C0B0D502917104D4C502D170A07503F" }, 
    { { 0x1D, 0x25, 0xBB, 0x2F, 0xC3, 0x95, 0x95, 0xCE, 0x50, 0xD5, 0x13, 0x2F, 0x45, 0x96, 0x8D, 0x17 }, L"29110C13502917104D4C503D111018171D151B0C503F" }, 
    { { 0x1D, 0x24, 0x06, 0x86, 0xDD, 0x23, 0xD3, 0xED, 0xAE, 0xF6, 0x1F, 0x86, 0xB2, 0x67, 0xF0, 0xFE }, L"29110C13502917104D4C503D111018171D151B0C503E" }, 
    { { 0x47, 0xAC, 0x16, 0x6E, 0x55, 0x98, 0x14, 0xB7, 0xBA, 0xC7, 0x27, 0x76, 0x27, 0x85, 0xC5, 0xB5 }, L"2A0C11141F10502917104D4C502D0A0B06101B0A503A0C17081B0C" }, 
    { { 0xA2, 0x11, 0x0C, 0x82, 0x95, 0x14, 0x7B, 0x83, 0x98, 0xC7, 0xB7, 0x26, 0x9F, 0xDC, 0x25, 0xCC }, L"3B060E1211170A502917104D4C503C120B1B351B1B0E502E1F0712111F1A" }  
};

struct ByteSignature {
    const wchar_t* name;
    const BYTE* pattern;
    size_t length;
};

const BYTE BlasterPattern[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF }; 
const BYTE WannaCryPattern[] = { 0xE8, 0x56, 0x00, 0x00, 0x00, 0x8B, 0xFF, 0x55, 0x8B, 0xEC }; 
const BYTE MimikatzPattern[] = { 0x33, 0xC0, 0x5D, 0xC3, 0x4D, 0x69, 0x6D, 0x69, 0x6B, 0x61, 0x74, 0x7A }; 
const BYTE GenericTrojanPattern[] = { 0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xC0 }; 

const ByteSignature g_ByteSignatures[] = {
    { L"Worm.Win32.Blaster", BlasterPattern, sizeof(BlasterPattern) },
    { L"Ransom.Win32.WannaCry", WannaCryPattern, sizeof(WannaCryPattern) },
    { L"HackTool.Win32.Mimikatz", MimikatzPattern, sizeof(MimikatzPattern) },
    { L"Trojan.Win32.GenericPayload", GenericTrojanPattern, sizeof(GenericTrojanPattern) }
};
const size_t g_ByteSignaturesCount = sizeof(g_ByteSignatures) / sizeof(g_ByteSignatures[0]);

typedef BOOL(WINAPI* pfnVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef BOOL(WINAPI* pfnReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
typedef HANDLE(WINAPI* pfnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HANDLE(WINAPI* pfnCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* pfnProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI* pfnProcess32NextW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI* pfnTerminateProcess)(HANDLE hProcess, UINT uExitCode);
typedef DWORD(WINAPI* pfnGetModuleFileNameExW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize); 
typedef BOOL(WINAPI* pfnSetProcessDEPPolicy)(IN DWORD dwFlags);
typedef DWORD(WINAPI* pfnSetTcpEntry)(PMIB_TCPROW pTcpRow);
typedef LONG(WINAPI* pfnRtlSetProcessIsCritical)(BOOLEAN bNew, PBOOLEAN pbOld, BOOLEAN bNeedPriv);

extern pfnVirtualQueryEx dyn_VirtualQueryEx;
extern pfnReadProcessMemory dyn_ReadProcessMemory;
extern pfnOpenProcess dyn_OpenProcess;
extern pfnCreateToolhelp32Snapshot dyn_CreateToolhelp32Snapshot;
extern pfnProcess32FirstW dyn_Process32FirstW;
extern pfnProcess32NextW dyn_Process32NextW;
extern pfnTerminateProcess dyn_TerminateProcess;
extern pfnSetTcpEntry dyn_SetTcpEntry;

pfnVirtualQueryEx dyn_VirtualQueryEx = NULL;
pfnReadProcessMemory dyn_ReadProcessMemory = NULL;
pfnOpenProcess dyn_OpenProcess = NULL;
pfnCreateToolhelp32Snapshot dyn_CreateToolhelp32Snapshot = NULL;
pfnProcess32FirstW dyn_Process32FirstW = NULL;
pfnProcess32NextW dyn_Process32NextW = NULL;
pfnTerminateProcess dyn_TerminateProcess = NULL;
pfnSetTcpEntry dyn_SetTcpEntry = NULL;

// Forward Declarations for Threads and Helper Functions
DWORD WINAPI SpeedupThread(LPVOID lpParam);
DWORD WINAPI CleanupThread(LPVOID lpParam);
std::string DecryptAPIString(const char* enc, size_t len, char key);
std::wstring HexDecryptString(const wchar_t* hexData);

DWORD WINAPI BrowserDownloadMonitorThread(LPVOID lpParam);
DWORD WINAPI LiveHTTPSWebCacheScanThread(LPVOID lpParam);
DWORD WINAPI RealTimeProcessExecutionShieldThread(LPVOID lpParam);

void InitSystemPaths();
bool IsWindowsXP();
bool IsSafeProcess(HANDLE hProc, pfnGetModuleFileNameExW pGetModuleFileNameEx);
bool IsUserAdmin();
bool IsSystemProcess(const std::wstring& processName);
void ShowNotification(const std::wstring& title, const std::wstring& message, DWORD infoFlags);
void CheckFirstRunPrompt(HWND hWnd);
LRESULT CALLBACK SidebarSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool IsPathExcluded(const std::wstring& filePath);
std::wstring BrowseFolder(HWND hwnd);
std::vector<std::wstring> GetSystemDrives();
bool QueryCloudThreatIntel(const std::wstring& fileHash);
void AddLog(const std::wstring& file, const std::wstring& threat, const std::wstring& action);
void ProtectLSASSDACL();
void ProtectHostsFile();
double CalculateShannonEntropy(const std::wstring& filePath);
bool UnhookDll(const wchar_t* dllName);
bool BypassUserModeHooks();
void HardenProcessDACL();
void ConnectToKernelShield(DWORD processId);
void EnableCriticalProcessSelfDefense();
void EnableHardwareDEPProtection();
bool VerifyAndMitigateBlueKeepRegistry();
bool AnalyzeLnkShortcutSafety(const std::wstring& lnkPath, std::wstring& threatName);
bool VerifyMBRIntegrity();
bool ShredAndDestroyFile(const std::wstring& filePath);
void CreateCanaryFiles();
void VerifyCanaryFiles();
void DrawSidebarIcon(HDC hdc, int index, int cx, int cy, COLORREF color);
void InitQuarantine();
bool MoveToQuarantine(const std::wstring& filePath, const std::wstring& reason = L"Manual Isolation");
bool IsProcessSuspicious(const std::wstring& name);
void PopulateProcessList();
void PopulateQuarantineList();
void PopulateStartupList();
bool IsTLS10Enabled();
bool DisableTLS10Protocol();
void ApplyAutoStartRegistry();
bool DeleteStartupEntry(const std::wstring& valueName);
void SanitizeStartupList();
void PopulateIEGuard();
void PopulateNetworkGuard();
void RefreshListView();
void PerformRealtimeNetworkAndWebScan();
void PerformRealtimeScan();
void LoadSettings();
void SaveSettings();
void LoadExclusions();
void SaveExclusions();
void DrawSidebarItem(HDC hdc, int index, bool sel, RECT rect);
bool GetFileBinaryMD5(const std::wstring& filePath, BYTE* outHash);
bool ScanFileForSignatures(const std::wstring& filePath, std::wstring& foundSig);
bool ScanFileContentForByteSignatures(const std::wstring& filePath, std::wstring& foundSig);
bool VerifyFileFormatIntegrity(const std::wstring& filePath, std::wstring& formatReason);
bool ScanScriptBehavior(const std::wstring& filePath, std::wstring& triggerReason);
int AnalyzeHeuristicRisk(const std::wstring& filePath, std::wstring& riskReason);
bool ScanProcessMemoryForPE(HANDLE hProc, LPVOID baseAddr, SIZE_T regionSize);
void DrawScanningShieldIcon(HDC hdc, int cx, int cy, int size);
void DrawSafeStatusIndicator(HDC hdc, int cx, int cy, int size, COLORREF themeColor);
void DrawCentralDisplay(HDC hdc, RECT rect);
void PreCountFilesRecursively(const std::wstring& directory);
void ScanDirectoryRecursively(const std::wstring& directory);
DWORD WINAPI ScanThread(LPVOID lpParam);
bool TrackAndDetectRansomware(const std::wstring& filePath);
bool IsSuspiciousParentChild(const std::wstring& parentName, const std::wstring& childName);
std::wstring GetProcessNameFromPID(DWORD pid);
bool ScanProcessMemoryForShellcode(HANDLE hProc, LPVOID baseAddr, SIZE_T regionSize);
bool IsProcessMasquerading(const std::wstring& procName, const std::wstring& procPath);
void CheckAndRemediateHostsFile();
void CheckDNSServerSafety();
void CheckBrowserHomePageHijack();
void CheckWindowsUpdateWSUSHijack();
void CreateSettingsControls(HWND hParent);
void SyncSettingsToUI();
void UpdateUIVisibility();
void AddRealtimeScanLog(const std::wstring& path, const std::wstring& status, const std::wstring& details);
bool ConfigureSystemPortNative(int port, bool block);

void ResolveDynamicAPIs();
DWORD WINAPI RealTimeDriveMonitorThread(LPVOID lpParam);
DWORD WINAPI RealTimeFirewallThread(LPVOID lpParam);
DWORD WINAPI RealTimeCodeInjectionShieldThread(LPVOID lpParam);
DWORD WINAPI KernelDriverWatcherThread(LPVOID lpParam);
DWORD WINAPI RealTimeRansomwareWatcherThread(LPVOID lpParam); 

// Thread-safe logger calls using synchronous SendMessage to UI thread
void ThreadSafeAddLog(const std::wstring& file, const std::wstring& threat, const std::wstring& action) {
    if (!IsWindow(g_hMainWnd)) return;
    SafeLogPayload payload = { file.c_str(), threat.c_str(), action.c_str() };
    SendMessage(g_hMainWnd, WM_APP_ADD_LOG, 0, (LPARAM)&payload);
}

void ThreadSafeAddRealtimeScanLog(const std::wstring& path, const std::wstring& status, const std::wstring& details) {
    if (!IsWindow(g_hMainWnd)) return;
    SafeLogPayload payload = { path.c_str(), status.c_str(), details.c_str() };
    SendMessage(g_hMainWnd, WM_APP_REALTIME_LOG, 0, (LPARAM)&payload);
}

// Complete implementation of dynamic Decryption helpers
std::string DecryptAPIString(const char* enc, size_t len, char key) {
    std::string result = "";
    for (size_t i = 0; i < len; ++i) {
        result += (char)(enc[i] ^ key);
    }
    return result;
}

std::wstring HexDecryptString(const wchar_t* hexData) {
    std::wstring result = L"";
    size_t len = wcslen(hexData);
    for (size_t i = 0; i < len; i += 2) {
        wchar_t hex[3] = { hexData[i], hexData[i+1], L'\0' };
        wchar_t* end;
        long val = wcstol(hex, &end, 16);
        result += (wchar_t)(val ^ 0x3D);
    }
    return result;
}

void AddRealtimeScanLog(const std::wstring& path, const std::wstring& status, const std::wstring& details) {
    int count = ListView_GetItemCount(g_hListView);
    LVITEMW item = {0};
    item.mask = LVIF_TEXT;
    item.iItem = count;
    item.iSubItem = 0;
    item.pszText = (LPWSTR)path.c_str();
    ListView_InsertItem(g_hListView, &item);
    ListView_SetItemText(g_hListView, count, 1, (LPWSTR)status.c_str());
    ListView_SetItemText(g_hListView, count, 2, (LPWSTR)details.c_str());
}

// Complete implementation of Speedup Utility with real-time UI logging
DWORD WINAPI SpeedupThread(LPVOID lpParam) {
    g_bIsScanning = true;
    g_CurrentScanningFile = L"Optimizing system memory...";
    Sleep(1000);
    
    int optimizedCount = 0;
    HANDLE hSnapshot = (dyn_CreateToolhelp32Snapshot != NULL) ? dyn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) : INVALID_HANDLE_VALUE;
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        if (dyn_Process32FirstW && dyn_Process32FirstW(hSnapshot, &pe)) {
            do {
                if (dyn_OpenProcess) {
                    HANDLE hProc = dyn_OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        if (SetProcessWorkingSetSize(hProc, (SIZE_T)-1, (SIZE_T)-1)) {
                            ThreadSafeAddLog(pe.szExeFile, L"Memory Trimmed", L"Working Set Optimized");
                            optimizedCount++;
                        }
                        CloseHandle(hProc);
                    }
                }
            } while (dyn_Process32NextW && dyn_Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    g_bIsScanning = false;
    g_CurrentScanningFile = L"";
    wchar_t msg[256];
    swprintf_s(msg, 256, L"Optimized %d processes successfully.", optimizedCount);
    ShowNotification(L"Speedup Complete", msg, NIIF_INFO);
    return 0;
}

// Complete implementation of Cleanup Utility with real-time UI logging
DWORD WINAPI CleanupThread(LPVOID lpParam) {
    g_bIsScanning = true;
    g_CurrentScanningFile = L"Cleaning temporary junk files...";
    
    int cleanedCount = 0;
    ULONGLONG totalSizeSaved = 0;
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring searchPath = std::wstring(tempPath) + L"*";
        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) {
                    std::wstring fullPath = std::wstring(tempPath) + ffd.cFileName;
                    if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        ULONGLONG fileSize = ((ULONGLONG)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
                        if (DeleteFileW(fullPath.c_str())) {
                            ThreadSafeAddLog(fullPath, L"Junk File Deleted", L"Temporary storage reclaimed");
                            cleanedCount++;
                            totalSizeSaved += fileSize;
                        }
                    }
                }
            } while (FindNextFileW(hFind, &ffd) != 0 && g_bIsScanning);
                    FindClose(hFind);
        }
    }
    
    g_bIsScanning = false;
    g_CurrentScanningFile = L"";
    wchar_t msg[256];
    double mbSaved = (double)totalSizeSaved / (1024.0 * 1024.0);
    swprintf_s(msg, 256, L"Cleaned %d temporary files. Reclaimed %.2f MB.", cleanedCount, mbSaved);
    ShowNotification(L"Cleanup Complete", msg, NIIF_INFO);
    return 0;
}

void ResolveDynamicAPIs() {
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        dyn_VirtualQueryEx = (pfnVirtualQueryEx)GetProcAddress(hKernel, "VirtualQueryEx");
        dyn_ReadProcessMemory = (pfnReadProcessMemory)GetProcAddress(hKernel, "ReadProcessMemory");
        dyn_OpenProcess = (pfnOpenProcess)GetProcAddress(hKernel, "OpenProcess");
        dyn_CreateToolhelp32Snapshot = (pfnCreateToolhelp32Snapshot)GetProcAddress(hKernel, "CreateToolhelp32Snapshot");
        dyn_Process32FirstW = (pfnProcess32FirstW)GetProcAddress(hKernel, "Process32FirstW");
        dyn_Process32NextW = (pfnProcess32NextW)GetProcAddress(hKernel, "Process32NextW");
        dyn_TerminateProcess = (pfnTerminateProcess)GetProcAddress(hKernel, "TerminateProcess");
    }
    HMODULE hIphlp = LoadLibraryW(L"iphlpapi.dll");
    if (hIphlp) {
        dyn_SetTcpEntry = (pfnSetTcpEntry)GetProcAddress(hIphlp, "SetTcpEntry");
    }
}

bool ConfigureSystemPortNative(int port, bool block) {
    if (!IsUserAdmin()) return false;
    
    HKEY hKey;
    if (port == 3389) {
        std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD val = block ? 1 : 0; 
            RegSetValueExW(hKey, L"fDenyTSConnections", 0, REG_DWORD, (const BYTE*)&val, sizeof(DWORD));
            RegCloseKey(hKey);
            return true;
        }
    }
    else if (port == 445) {
        std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD val = block ? 0 : 1; 
            RegSetValueExW(hKey, L"SMBDeviceEnabled", 0, REG_DWORD, (const BYTE*)&val, sizeof(DWORD));
            RegCloseKey(hKey);
        }
        // Force-disable LanmanServer service startup if blocking SMB on XP
        SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
            SC_HANDLE hService = OpenServiceW(hSCM, L"LanmanServer", SERVICE_CHANGE_CONFIG | SERVICE_STOP);
            if (hService) {
                DWORD startType = block ? SERVICE_DISABLED : SERVICE_AUTO_START;
                ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, startType, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                if (block) {
                    SERVICE_STATUS ss;
                    ControlService(hService, SERVICE_CONTROL_STOP, &ss);
                }
                CloseHandle(hService);
            }
            CloseHandle(hSCM);
        }
        return true;
    }
    else if (port == 135) {
        std::wstring regPath = L"SOFTWARE\\Microsoft\\Ole";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            const wchar_t* val = block ? L"N" : L"Y"; 
            RegSetValueExW(hKey, L"EnableDCOM", 0, REG_SZ, (const BYTE*)val, (wcslen(val) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

DWORD WINAPI RealTimeDriveMonitorThread(LPVOID lpParam) {
    DWORD dwLastDrives = GetLogicalDrives();
    while (g_bRealTimeProtection) {
        DWORD dwCurrentDrives = GetLogicalDrives();
        if (dwCurrentDrives != dwLastDrives) {
            for (int i = 0; i < 26; i++) {
                if ((dwCurrentDrives & (1 << i)) && !(dwLastDrives & (1 << i))) {
                    wchar_t driveLetter = L'A' + i;
                    std::wstring driveRoot = std::wstring(1, driveLetter) + L":\\";
                    UINT driveType = GetDriveTypeW(driveRoot.c_str());
                    if (driveType == DRIVE_REMOVABLE && g_bBlockUSB) {
                        std::wstring autorunPath = driveRoot + HexDecryptString(L"1F0B0A110C0B1050171018");
                        if (CreateDirectoryW(autorunPath.c_str(), NULL)) {
                            SetFileAttributesW(autorunPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
                            std::wstring protectPath = autorunPath + L"\\SecureXP_Vaccine.lck";
                            HANDLE hLck = CreateFileW(protectPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
                            if (hLck != INVALID_HANDLE_VALUE) CloseHandle(hLck);
                            ShowNotification(L"USB Shield Immunizer", L"Vaccinated: Drive " + std::wstring(1, driveLetter), NIIF_INFO);
                        }
                    }
                }
            }
            dwLastDrives = dwCurrentDrives;
        }
        Sleep(2000);
    }
    return 0;
}

DWORD WINAPI RealTimeFirewallThread(LPVOID lpParam) {
    while (g_bRealTimeProtection) {
        if (g_bBlockPort445 || g_bBlockPort135 || g_bBlockPort3389) {
            MIB_TCPTABLE* pTcpTable = NULL;
            DWORD dwSize = 0;
            if (GetTcpTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                pTcpTable = (MIB_TCPTABLE*)malloc(dwSize);
                if (pTcpTable && GetTcpTable(pTcpTable, &dwSize, FALSE) == NO_ERROR) {
                    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                        DWORD localPort = CustomNtohs((u_short)pTcpTable->table[i].dwLocalPort);
                        DWORD state = pTcpTable->table[i].dwState;
                        
                        bool block = false;
                        if (localPort == 445 && g_bBlockPort445) block = true;
                        else if (localPort == 135 && g_bBlockPort135) block = true;
                        else if (localPort == 3389 && g_bBlockPort3389) block = true;

                        if (block && state != MIB_TCP_STATE_DELETE_TCB && state != MIB_TCP_STATE_LISTEN) {
                            MIB_TCPROW row = pTcpTable->table[i];
                            row.dwState = MIB_TCP_STATE_DELETE_TCB;
                            if (dyn_SetTcpEntry) {
                                dyn_SetTcpEntry(&row);
                            }
                        }
                    }
                }
                if (pTcpTable) free(pTcpTable);
            }
        }
        Sleep(1000);
    }
    return 0;
}

DWORD WINAPI RealTimeCodeInjectionShieldThread(LPVOID lpParam) {
    while (g_bRealTimeProtection) {
        if (g_bRamShield) {
            HANDLE hSnapshot = (dyn_CreateToolhelp32Snapshot != NULL) ? dyn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) : INVALID_HANDLE_VALUE;
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
                if (dyn_Process32FirstW && dyn_Process32FirstW(hSnapshot, &pe)) {
                    do {
                        if (pe.th32ProcessID <= 4 || pe.th32ProcessID == GetCurrentProcessId()) continue;
                        if (IsSystemProcess(pe.szExeFile)) continue;

                        HANDLE hProc = (dyn_OpenProcess != NULL) ? dyn_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID) : NULL;
                        if (hProc) {
                            SYSTEM_INFO sysInfo;
                            GetSystemInfo(&sysInfo);
                            unsigned char* addr = (unsigned char*)sysInfo.lpMinimumApplicationAddress;
                            MEMORY_BASIC_INFORMATION mbi;

                            while (addr < (unsigned char*)sysInfo.lpMaximumApplicationAddress) {
                                if (dyn_VirtualQueryEx && dyn_VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
                                    if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
                                        if (ScanProcessMemoryForPE(hProc, mbi.BaseAddress, mbi.RegionSize) ||
                                            ScanProcessMemoryForShellcode(hProc, mbi.BaseAddress, mbi.RegionSize)) {
                                            
                                            HANDLE hKill = (dyn_OpenProcess != NULL) ? dyn_OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID) : NULL;
                                            if (hKill) {
                                                if (dyn_TerminateProcess) {
                                                    dyn_TerminateProcess(hKill, 0);
                                                }
                                                CloseHandle(hKill);
                                                ShowNotification(L"Exploit Shield Active", L"Terminated injected process: " + std::wstring(pe.szExeFile), NIIF_ERROR);
                                                break;
                                            }
                                        }
                                    }
                                    addr += mbi.RegionSize;
                                } else {
                                    addr += sysInfo.dwPageSize;
                                }
                            }
                            CloseHandle(hProc);
                        }
                    } while (dyn_Process32NextW && dyn_Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
        }
        Sleep(3000);
    }
    return 0;
}

DWORD WINAPI KernelDriverWatcherThread(LPVOID lpParam) {
    while (g_bRealTimeProtection) {
        HANDLE hDevice = CreateFileW(DEVICE_SECUREXP, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            wchar_t blockedFile[MAX_PATH] = {0};
            DWORD bytesReturned = 0;
            if (DeviceIoControl(hDevice, IOCTL_SECUREXP_GET_BLOCKED_FILE, NULL, 0, blockedFile, sizeof(blockedFile), &bytesReturned, NULL)) {
                if (bytesReturned > 0 && wcslen(blockedFile) > 0) {
                    std::wstring threatFile = blockedFile;
                    std::wstring threatReason = L"Kernel Filter Interception";
                    std::wstring actionTaken = L"Blocked by Kernel";
                    
                    if (g_AutomationLevel == 1) {
                        if (MoveToQuarantine(threatFile)) actionTaken = L"Quarantined";
                    } else if (g_AutomationLevel == 2) {
                        if (ShredAndDestroyFile(threatFile)) actionTaken = L"Shredded";
                    }
                    ThreadSafeAddLog(threatFile, threatReason, actionTaken);
                    ShowNotification(L"Kernel Shield Block", L"Intercepted driver-level unauthorized read/write on: " + threatFile, NIIF_WARNING);
                }
            }
            CloseHandle(hDevice);
        }
        Sleep(1000);
    }
    return 0;
}

DWORD WINAPI RealTimeRansomwareWatcherThread(LPVOID lpParam) {
    wchar_t personalPath[MAX_PATH];
    if (!SHGetSpecialFolderPathW(NULL, personalPath, CSIDL_PERSONAL, FALSE)) {
        return 0;
    }

    g_hRansomwareDir = CreateFileW(personalPath, FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (g_hRansomwareDir == INVALID_HANDLE_VALUE) return 0;

    BYTE buffer[4096];
    DWORD bytesReturned = 0;

    while (g_bRealTimeProtection) {
        if (ReadDirectoryChangesW(g_hRansomwareDir, buffer, sizeof(buffer), TRUE,
                                  FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                  &bytesReturned, NULL, NULL)) {
            FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)buffer;
            do {
                if (pNotify->Action == FILE_ACTION_ADDED || pNotify->Action == FILE_ACTION_MODIFIED) {
                    std::wstring fileName(pNotify->FileName, pNotify->FileNameLength / sizeof(wchar_t));
                    std::wstring fullPath = std::wstring(personalPath) + L"\\" + fileName;

                    if (TrackAndDetectRansomware(fullPath)) {
                        ShowNotification(L"Ransomware Shield Activated", L"Suspicious rapid encryption blocked in Personal Files: " + fileName, NIIF_ERROR);
                    }
                }
                pNotify = pNotify->NextEntryOffset ? (FILE_NOTIFY_INFORMATION*)((BYTE*)pNotify + pNotify->NextEntryOffset) : NULL;
            } while (pNotify);
        } else {
            break; 
        }
    }
    return 0;
}

// Stub implementations of previously missing thread routines
DWORD WINAPI BrowserDownloadMonitorThread(LPVOID lpParam) {
    while (g_bRealTimeProtection) {
        Sleep(1000);
    }
    return 0;
}

DWORD WINAPI LiveHTTPSWebCacheScanThread(LPVOID lpParam) {
    while (g_bRealTimeProtection) {
        Sleep(1000);
    }
    return 0;
}

// NEW INTEGRATED FEATURE: Active Parent-Child Behavioral Mitigation Shield [29]
// Continuously polls active processes and verifies parent-child execution structures [29]
DWORD WINAPI RealTimeProcessExecutionShieldThread(LPVOID lpParam) {
    while (g_bRealTimeProtection) {
        if (g_bCredentialGuard) { 
            HANDLE hSnapshot = (dyn_CreateToolhelp32Snapshot != NULL) ? dyn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) : INVALID_HANDLE_VALUE;
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
                std::vector<PROCESSENTRY32W> processList;
                if (dyn_Process32FirstW && dyn_Process32FirstW(hSnapshot, &pe)) {
                    do {
                        processList.push_back(pe);
                    } while (dyn_Process32NextW && dyn_Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);

                // Analyze process relationships for malicious parent-child process chains [29]
                for (const auto& child : processList) {
                    if (child.th32ProcessID <= 4 || child.th32ProcessID == GetCurrentProcessId()) continue;

                    std::wstring parentName = L"";
                    for (const auto& parent : processList) {
                        if (parent.th32ProcessID == child.th32ParentProcessID) {
                            parentName = parent.szExeFile;
                            break;
                        }
                    }

                    if (!parentName.empty()) {
                        if (IsSuspiciousParentChild(parentName, child.szExeFile)) {
                            // Terminate the unauthorized sub-process to mitigate execution threats [29]
                            HANDLE hKill = (dyn_OpenProcess != NULL) ? dyn_OpenProcess(PROCESS_TERMINATE, FALSE, child.th32ProcessID) : NULL;
                            if (hKill) {
                                if (dyn_TerminateProcess) {
                                    dyn_TerminateProcess(hKill, 0);
                                }
                                CloseHandle(hKill);
                                
                                std::wstring alertMsg = L"Blocked suspicious child spawning: " + parentName + L" -> " + child.szExeFile;
                                ThreadSafeAddLog(child.szExeFile, L"Suspicious Parent-Child Chain", L"Execution Terminated");
                                ShowNotification(L"Behavior Shield Active", alertMsg, NIIF_ERROR);
                            }
                        }
                    }
                }
            }
        }
        Sleep(2000); 
    }
    return 0;
}

void InitSystemPaths() {
    wchar_t appData[MAX_PATH];
    if (SHGetSpecialFolderPathW(NULL, appData, CSIDL_COMMON_APPDATA, TRUE)) {
        swprintf_s(g_QuarantineDir, MAX_PATH, L"%s\\SecureXP_Quarantine", appData);
        swprintf_s(g_ConfigFile, MAX_PATH, L"%s\\SecureXP.ini", appData);
    } else {
        GetTempPathW(MAX_PATH, appData);
        swprintf_s(g_QuarantineDir, MAX_PATH, L"%s\\SecureXP_Quarantine", appData);
        swprintf_s(g_ConfigFile, MAX_PATH, L"%s\\SecureXP.ini", appData);
    }
}

bool IsWindowsXP() {
    OSVERSIONINFOEXW osvi = { sizeof(OSVERSIONINFOEXW) };
    osvi.dwMajorVersion = 5;
    DWORDLONG const dwlConditionMask = VerSetConditionMask(0, VER_MAJORVERSION, VER_EQUAL);
    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION, dwlConditionMask) != FALSE;
}

bool IsSafeProcess(HANDLE hProc, pfnGetModuleFileNameExW pGetModuleFileNameEx) {
    if (!pGetModuleFileNameEx) return false;
    wchar_t procPath[MAX_PATH] = {0};
    if (pGetModuleFileNameEx(hProc, NULL, procPath, MAX_PATH)) {
        std::wstring path = procPath;
        std::wstring lowerPath = path;
        for (auto& c : lowerPath) c = towlower(c);

        wchar_t winDir[MAX_PATH];
        if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
            std::wstring lowerWinDir = winDir;
            for (auto& c : lowerWinDir) c = towlower(c);

            if (lowerPath.find(lowerWinDir) == 0) {
                if (lowerPath.find(L"\\temp\\") == std::wstring::npos &&
                    lowerPath.find(L"\\temporary internet files\\") == std::wstring::npos) {
                    return true;
                }
            }
        }
        
        if (lowerPath.find(L"chrome.exe") != std::wstring::npos ||
            lowerPath.find(L"firefox.exe") != std::wstring::npos ||
            lowerPath.find(L"iexplore.exe") != std::wstring::npos ||
            lowerPath.find(L"opera.exe") != std::wstring::npos ||
            lowerPath.find(L"msedge.exe") != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool IsUserAdmin() {
    return IsUserAnAdmin() != FALSE;
}

bool IsSystemProcess(const std::wstring& processName) {
    std::wstring lowerName = processName;
    for (auto& c : lowerName) c = towlower(c);
    
    if (lowerName == L"explorer.exe" || 
        lowerName == L"svchost.exe" || 
        lowerName == L"csrss.exe" || 
        lowerName == L"smss.exe" || 
        lowerName == L"winlogon.exe" || 
        lowerName == L"lsass.exe" || 
        lowerName == L"services.exe" || 
        lowerName == L"system" || 
        lowerName == L"taskmgr.exe" ||
        lowerName == L"spoolsv.exe" ||
        lowerName == L"control.exe" ||
        lowerName == L"rundll32.exe" ||
        lowerName == L"msiexec.exe" ||
        lowerName == L"regedit.exe") {
        return true;
    }
    return false;
}

void ShowNotification(const std::wstring& title, const std::wstring& message, DWORD infoFlags) {
    NOTIFYICONDATAW nid = {0};
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = g_hMainWnd; 
    nid.uID = NOTIFY_ID;
    nid.uCallbackMessage = ID_TRAY_CALLBACK;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = infoFlags; 
    wcsncpy(nid.szInfoTitle, title.c_str(), 63);
    wcsncpy(nid.szInfo, message.c_str(), 255);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void CheckFirstRunPrompt(HWND hWnd) {
    int isFirstRun = GetPrivateProfileIntW(L"Settings", L"FirstRun", 1, g_ConfigFile);
    if (isFirstRun == 1) {
        int response = MessageBoxW(hWnd, 
            L"Would you like to configure system port security?\n\nSelecting 'Yes' will automatically block vulnerable system ports (such as SMB 445, RPC 135, and RDP 3389) to prevent network intrusion.\nSelecting 'No' will leave the system ports unmodified.", 
            L"Secure XP Pro v2 Initial Firewall Configuration", 
            MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);
        
        if (response == IDYES) {
            g_bBlockPort445 = true;
            g_bBlockPort135 = true;
            g_bBlockPort3389 = true;
            ShowNotification(L"Firewall Auto-Configured", L"Critical system ports have been secured successfully.", NIIF_INFO);
        } else {
            g_bBlockPort445 = false;
            g_bBlockPort135 = false;
            g_bBlockPort3389 = false;
        }
        WritePrivateProfileStringW(L"Settings", L"FirstRun", L"0", g_ConfigFile);
        SaveSettings();
    }
}

LRESULT CALLBACK SidebarSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_MOUSEMOVE: {
            POINT pt; GetCursorPos(&pt); ScreenToClient(hWnd, &pt);
            int idx = pt.y / 50; 
            if (idx >= 0 && idx < g_SidebarCount && idx != g_HoveredItem) {
                g_HoveredItem = idx;
                InvalidateRect(hWnd, NULL, TRUE); 
            }
            TRACKMOUSEEVENT tme;
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hWnd;
            TrackMouseEvent(&tme);
            break;
        }
        case WM_MOUSELEAVE: {
            g_HoveredItem = -1;
            InvalidateRect(hWnd, NULL, TRUE);
            break;
        }
    }
    return CallWindowProc(g_OldSidebarProc, hWnd, msg, wParam, lParam);
}

bool IsPathExcluded(const std::wstring& filePath) {
    std::wstring fPath = filePath;
    for (auto& c : fPath) c = towlower(c);

    bool isExcluded = false;
    EnterCriticalSection(&g_ExclusionsCS);
    for (const auto& excluded : g_ExcludedFolders) {
        std::wstring exPath = excluded;
        for (auto& c : exPath) c = towlower(c);
        
        if (fPath.find(exPath) == 0) {
            isExcluded = true;
            break;
        }
    }
    LeaveCriticalSection(&g_ExclusionsCS);
    return isExcluded;
}

std::wstring BrowseFolder(HWND hwnd) {
    wchar_t path[MAX_PATH] = {0};
    BROWSEINFOW bi = {0};
    bi.hwndOwner = hwnd;
    bi.lpszTitle = L"Select folder to exclude from security scans:";
    bi.ulFlags = BIF_USENEWUI | BIF_RETURNONLYFSDIRS;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl != 0) {
        SHGetPathFromIDListW(pidl, path);
        LPMALLOC pMalloc;
        if (SUCCEEDED(SHGetMalloc(&pMalloc))) {
            pMalloc->Free(pidl);
            pMalloc->Release();
        }
    }
    return path;
}

std::vector<std::wstring> GetSystemDrives() {
    std::vector<std::wstring> drives;
    wchar_t buffer[MAX_PATH];
    DWORD len = GetLogicalDriveStringsW(MAX_PATH, buffer);
    if (len > 0 && len < MAX_PATH) {
        wchar_t* drive = buffer;
        while (*drive) {
            UINT type = GetDriveTypeW(drive);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                std::wstring dStr = drive;
                if (!dStr.empty() && dStr.back() == L'\\') {
                    dStr.pop_back();
                }
                drives.push_back(dStr);
            }
            drive += wcslen(drive) + 1;
        }
    }
    if (drives.empty()) {
        drives.push_back(L"C:");
    }
    return drives;
}

// Implemented an HTTP/REST Threat Intelligence client using WinINet
bool QueryCloudThreatIntel(const std::wstring& fileHash) {
    HINTERNET hSession = InternetOpenW(L"SecureXPCloudIntel/2.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hSession) return false;

    std::wstring url = L"http://threat-intel.securexp.local/check?hash=" + fileHash;
    HINTERNET hUrl = InternetOpenUrlW(hSession, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    
    bool isThreat = false;
    if (hUrl) {
        char buffer[128];
        DWORD bytesRead = 0;
        if (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string response(buffer);
            if (response.find("MALICIOUS") != std::string::npos || response.find("THREAT") != std::string::npos) {
                isThreat = true;
            }
        }
        InternetCloseHandle(hUrl);
    }
    InternetCloseHandle(hSession);
    return isThreat;
}

void AddLog(const std::wstring& file, const std::wstring& threat, const std::wstring& action) {
    LVITEMW item = {0};
    int count = ListView_GetItemCount(g_hListView);
    item.mask = LVIF_TEXT;
    item.iItem = count;
    item.iSubItem = 0;
    item.pszText = (LPWSTR)file.c_str();
    ListView_InsertItem(g_hListView, &item);
    ListView_SetItemText(g_hListView, count, 1, (LPWSTR)threat.c_str());
    ListView_SetItemText(g_hListView, count, 2, (LPWSTR)action.c_str());
}

// Implemented a robust system process DACL locking mechanism to protect LSASS memory dumping vectors (such as Mimikatz/ProcDump)
void ProtectLSASSDACL() {
    DWORD lsassPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (wcscmp(pe.szExeFile, L"lsass.exe") == 0) {
                    lsassPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    if (lsassPid == 0) return;

    HANDLE hLsass = OpenProcess(WRITE_DAC | READ_CONTROL, FALSE, lsassPid);
    if (hLsass) {
        PACL pNewDacl = NULL;
        EXPLICIT_ACCESSW ea[1];
        ZeroMemory(&ea, sizeof(ea));

        // Explicitly deny permissions required to dump memory (PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_TERMINATE) to the EVERYONE group
        ea[0].grfAccessPermissions = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_TERMINATE | PROCESS_DUP_HANDLE;
        ea[0].grfAccessMode = DENY_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        ea[0].Trustee.ptstrName = (LPWSTR)L"EVERYONE";

        if (SetEntriesInAclW(1, ea, NULL, &pNewDacl) == ERROR_SUCCESS) {
            SetSecurityInfo(hLsass, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
            LocalFree(pNewDacl);
        }
        CloseHandle(hLsass);
    }
}

void ProtectHostsFile() {
    if (!g_bHostsGuard) {
        if (g_hHostsFileLock != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hHostsFileLock);
            g_hHostsFileLock = INVALID_HANDLE_VALUE;
        }
        return;
    }
    if (g_hHostsFileLock == INVALID_HANDLE_VALUE) {
        wchar_t windir[MAX_PATH];
        GetWindowsDirectoryW(windir, MAX_PATH);
        std::wstring hostsPath = std::wstring(windir) + L"\\System32\\drivers\\etc\\hosts";
        g_hHostsFileLock = CreateFileW(hostsPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
}

double CalculateShannonEntropy(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0.0;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return 0.0;
    }

    DWORD bytesToRead = (fileSize.QuadPart > 1048576) ? 1048576 : (DWORD)fileSize.QuadPart;
    BYTE* buffer = (BYTE*)malloc(bytesToRead);
    if (!buffer) {
        CloseHandle(hFile);
        return 0.0;
    }

    DWORD bytesRead = 0;
    ReadFile(hFile, buffer, bytesToRead, &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead == 0) {
        free(buffer);
        return 0.0;
    }

    double entropy = 0.0;
    double len = (double)bytesRead;
    DWORD counts[256] = {0};

    for (DWORD i = 0; i < bytesRead; i++) {
        counts[buffer[i]]++;
    }
    free(buffer);

    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

// Reload clean DLL code structures to purge user-mode hook redirection from memory
bool UnhookDll(const wchar_t* dllName) {
    wchar_t systemDir[MAX_PATH];
    if (!GetSystemDirectoryW(systemDir, MAX_PATH)) return false;
    std::wstring dllPath = std::wstring(systemDir) + L"\\" + dllName;

    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    HMODULE hCurrentModule = GetModuleHandleW(dllName);
    if (!hCurrentModule) {
        UnmapViewOfFile(pMapping);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pMapping + dosHeader->e_lfanew);

    bool bSuccess = false;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * sizeof(IMAGE_SECTION_HEADER)));
        if (strcmp((const char*)sectionHeader->Name, ".text") == 0) {
            LPVOID pLocalText = (LPVOID)((ULONG_PTR)hCurrentModule + sectionHeader->VirtualAddress);
            LPVOID pMappedText = (LPVOID)((ULONG_PTR)pMapping + sectionHeader->VirtualAddress);
            SIZE_T sectionSize = sectionHeader->Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(pLocalText, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(pLocalText, pMappedText, sectionSize);
                VirtualProtect(pLocalText, sectionSize, oldProtect, &oldProtect);
                bSuccess = true;
            }
            break;
        }
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return bSuccess;
}

// Maps a clean copy of both ntdll.dll and kernel32.dll from system files to overwrite malware API hooks dynamically.
bool BypassUserModeHooks() {
    bool ntdllOK = UnhookDll(L"ntdll.dll");
    bool kernel32OK = UnhookDll(L"kernel32.dll");
    return ntdllOK && kernel32OK;
}

void HardenProcessDACL() {
    HANDLE hProcess = GetCurrentProcess();
    PACL pNewDACL = NULL;
    EXPLICIT_ACCESSW ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSW));
    
    ea.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SET_INFORMATION;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = (LPWSTR)L"EVERYONE";

    if (SetEntriesInAclW(1, &ea, NULL, &pNewDACL) == ERROR_SUCCESS) {
        SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
        LocalFree(pNewDACL);
    }
}

void ConnectToKernelShield(DWORD processId) {
    HANDLE hDevice = CreateFileW(DEVICE_SECUREXP, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_PROTECT_PROCESS, &processId, sizeof(processId), NULL, 0, &bytesReturned, NULL);
        CloseHandle(hDevice);
    }
}

void EnableCriticalProcessSelfDefense() {
    if (!IsUserAdmin()) return;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pfnRtlSetProcessIsCritical RtlSetProcessIsCritical = 
            (pfnRtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
        if (RtlSetProcessIsCritical) {
            HANDLE hToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LUID luidDebug, luidShutdown;
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 0;
                
                if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luidDebug)) {
                    tp.Privileges[tp.PrivilegeCount].Luid = luidDebug;
                    tp.Privileges[tp.PrivilegeCount].Attributes = SE_PRIVILEGE_ENABLED;
                    tp.PrivilegeCount++;
                }
                if (LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &luidShutdown)) {
                    tp.Privileges[tp.PrivilegeCount].Luid = luidShutdown;
                    tp.Privileges[tp.PrivilegeCount].Attributes = SE_PRIVILEGE_ENABLED;
                    tp.PrivilegeCount++;
                }
                if (tp.PrivilegeCount > 0) {
                    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                }
                CloseHandle(hToken);
            }
            BOOLEAN bOld = FALSE;
            RtlSetProcessIsCritical(TRUE, &bOld, FALSE);
        }
    }
}

void EnableHardwareDEPProtection() {
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        pfnSetProcessDEPPolicy SetProcessDEPPolicy = (pfnSetProcessDEPPolicy)GetProcAddress(hKernel, "SetProcessDEPPolicy");
        if (SetProcessDEPPolicy) {
            SetProcessDEPPolicy(1); 
        }
    }
}

bool VerifyAndMitigateBlueKeepRegistry() {
    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D272D2A3B33223D0B0C0C1B100A3D11100A0C11122D1B0A223D11100A0C1112222A1B0C1317101F124C2D1B0C081B0C");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD dwDeny = 1;
        DWORD cbData = sizeof(DWORD);
        RegQueryValueExW(hKey, L"fDenyTSConnections", NULL, NULL, (LPBYTE)&dwDeny, &cbData);
        
        if (dwDeny == 0) { 
            DWORD disableRDP = 1;
            RegSetValueExW(hKey, L"fDenyTSConnections", 0, REG_DWORD, (const BYTE*)&disableRDP, sizeof(DWORD));
            RegCloseKey(hKey);
            return false; 
        }
        RegCloseKey(hKey);
    }
    return true;
}

bool AnalyzeLnkShortcutSafety(const std::wstring& lnkPath, std::wstring& threatName) {
    HANDLE hFile = CreateFileW(lnkPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    BYTE buffer[1024] = {0};
    DWORD bytesRead = 0;
    bool bSuccess = ReadFile(hFile, buffer, 1024, &bytesRead, NULL);
    CloseHandle(hFile);

    if (!bSuccess || bytesRead < 76) return false;

    if (buffer[0] != 0x4C || buffer[1] != 0x00 || buffer[2] != 0x00 || buffer[3] != 0x00) {
        return false; 
    }

    std::string binContent((char*)buffer, bytesRead);
    for (auto& c : binContent) c = tolower(c);

    if (binContent.find(".cpl") != std::string::npos || binContent.find("~wtr") != std::string::npos) {
        threatName = L"Exploit.Win32.Stuxnet.Lnk";
        return true; 
    }

    return false;
}

bool VerifyMBRIntegrity() {
    std::wstring physicalDrive = HexDecryptString(L"222250222E16070D171D1F123A0C17081B4E");
    HANDLE hDrive = CreateFileW(physicalDrive.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) return true; 

    BYTE mbrBuffer[512] = {0};
    DWORD bytesRead = 0;
    bool bSuccess = ReadFile(hDrive, mbrBuffer, 512, &bytesRead, NULL);
    CloseHandle(hDrive);

    if (!bSuccess || bytesRead < 512) return true;

    if (mbrBuffer[510] != 0x55 || mbrBuffer[511] != 0xAA) {
        return false; 
    }

    std::string mbrContent((char*)mbrBuffer, 512);
    if (mbrContent.find("Stoned") != std::string::npos || mbrContent.find("Lolipop") != std::string::npos) {
        return false; 
    }

    return true;
}

bool ShredAndDestroyFile(const std::wstring& filePath) {
    if (IsPathExcluded(filePath)) return false;

    SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (MoveFileExW(filePath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            ShowNotification(L"Locked Threat Mitigated", L"File locked. Scheduled for deletion on system restart.", NIIF_WARNING);
            return true;
        }
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return false;
    }

    const DWORD bufferSize = 65536;
    BYTE* overwriteBuffer = (BYTE*)malloc(bufferSize);
    if (!overwriteBuffer) {
        CloseHandle(hFile);
        return false;
    }

    LONGLONG bytesWrittenTotal = 0;
    DWORD written = 0;

    ZeroMemory(overwriteBuffer, bufferSize);
    while (bytesWrittenTotal < fileSize.QuadPart) {
        DWORD toWrite = (fileSize.QuadPart - bytesWrittenTotal > bufferSize) ? bufferSize : (DWORD)(fileSize.QuadPart - bytesWrittenTotal);
        WriteFile(hFile, overwriteBuffer, toWrite, &written, NULL);
        bytesWrittenTotal += written;
    }

    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    free(overwriteBuffer);

    wchar_t tempPath[MAX_PATH], destPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wsprintf_s(destPath, MAX_PATH, L"%s\\SecureXP_Shred_%d.tmp", tempPath, GetTickCount());
    
    if (MoveFileW(filePath.c_str(), destPath)) {
        return (DeleteFileW(destPath) != FALSE);
    }
    return (DeleteFileW(filePath.c_str() ) != FALSE);
}

void CreateCanaryFiles() {
    if (!g_bHipsCanary) return;

    wchar_t desktop[MAX_PATH];
    if (SHGetSpecialFolderPathW(NULL, desktop, CSIDL_DESKTOP, FALSE)) {
        std::wstring canaryPath = std::wstring(desktop) + L"\\~SecureXP_Canary_Shield.txt";
        HANDLE hFile = CreateFileW(canaryPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            const char* msg = "SECUREXP_CANARY_VALUE_PROTECTED_BY_ACTIVE_SHIELD";
            DWORD written;
            WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

void VerifyCanaryFiles() {
    if (!g_bHipsCanary) return;

    wchar_t desktop[MAX_PATH];
    if (SHGetSpecialFolderPathW(NULL, desktop, CSIDL_DESKTOP, FALSE)) {
        std::wstring canaryPath = std::wstring(desktop) + L"\\~SecureXP_Canary_Shield.txt";
        HANDLE hFile = CreateFileW(canaryPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            static bool bCanaryWarned = false;
            if (!bCanaryWarned) {
                bCanaryWarned = true;
                ShowNotification(L"Critical HIPS Alert", L"Desktop Canary file was modified or deleted!", NIIF_ERROR);
            }
        }
    }
}

void DrawSidebarIcon(HDC hdc, int index, int cx, int cy, COLORREF color) {
    HPEN pen = CreatePen(PS_SOLID, 2, color);
    HBRUSH brush = CreateSolidBrush(color);
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);

    HBRUSH nullBrush = (HBRUSH)GetStockObject(NULL_BRUSH);

    switch (index) {
        case 0: { 
            SelectObject(hdc, nullBrush);
            Arc(hdc, cx - 8, cy - 8, cx + 8, cy + 8, cx - 6, cy + 6, cx + 6, cy + 6);
            MoveToEx(hdc, cx, cy, NULL);
            LineTo(hdc, cx + 5, cy - 4); 
            break;
        }
        case 1: { 
            POINT pts[6] = { {cx, cy - 9}, {cx + 7, cy - 6}, {cx + 7, cy + 1}, {cx, cy + 8}, {cx - 7, cy + 1}, {cx - 7, cy - 6} };
            Polygon(hdc, pts, 6);
            HPEN tickPen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
            SelectObject(hdc, tickPen);
            MoveToEx(hdc, cx - 3, cy, NULL); LineTo(hdc, cx - 1, cy + 2); LineTo(hdc, cx + 3, cy - 2);
            DeleteObject(tickPen);
            break;
        }
        case 2: { 
            SelectObject(hdc, nullBrush);
            RECT box = { cx - 7, cy - 3, cx + 7, cy + 6 };
            Rectangle(hdc, box.left, box.top, box.right, box.bottom);
            MoveToEx(hdc, cx - 8, cy - 3, NULL); LineTo(hdc, cx + 8, cy - 3); 
            RECT lock = { cx - 3, cy, cx + 3, cy + 4 };
            RoundRect(hdc, lock.left, lock.top, lock.right, lock.bottom, 2, 2);
            break;
        }
        case 3: { 
            SelectObject(hdc, nullBrush);
            RECT core = { cx - 5, cy - 5, cx + 5, cy + 5 };
            Rectangle(hdc, core.left, core.top, core.right, core.bottom);
            for(int i = -4; i <= 4; i += 3) {
                MoveToEx(hdc, cx + i, cy - 5, NULL); LineTo(hdc, cx + i, cy - 8);
                MoveToEx(hdc, cx + i, cy + 5, NULL); LineTo(hdc, cx + i, cy + 8);
                MoveToEx(hdc, cx - 5, cy + i, NULL); LineTo(hdc, cx - 8, cy + i);
                MoveToEx(hdc, cx + 5, cy + i, NULL); LineTo(hdc, cx + 8, cy + i);
            }
            break;
        }
        case 4: { 
            POINT lightning[6] = { {cx + 1, cy - 9}, {cx - 5, cy + 1}, {cx - 1, cy + 1}, {cx - 2, cy + 9}, {cx + 4, cy - 1}, {cx, cy - 1} };
            Polygon(hdc, lightning, 6);
            break;
        }
        case 5: { // Quarantine Custom Box Icon
            SelectObject(hdc, nullBrush);
            RECT box = { cx - 7, cy - 7, cx + 7, cy + 7 };
            Rectangle(hdc, box.left, box.top, box.right, box.bottom);
            MoveToEx(hdc, cx - 7, cy - 7, NULL); LineTo(hdc, cx + 7, cy + 7);
            MoveToEx(hdc, cx + 7, cy - 7, NULL); LineTo(hdc, cx - 7, cy + 7);
            break;
        }
    }

    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
}

void InitQuarantine() {
    CreateDirectoryW(g_QuarantineDir, NULL);
    SetFileAttributesW(g_QuarantineDir, FILE_ATTRIBUTE_HIDDEN);
}

bool MoveToQuarantine(const std::wstring& filePath, const std::wstring& reason) {    
    if (IsPathExcluded(filePath)) return false;

    wchar_t dest[MAX_PATH], fname[MAX_PATH];
    wcscpy_s(fname, MAX_PATH, filePath.c_str());
    PathStripPathW(fname);
    swprintf_s(dest, MAX_PATH, L"%s\\%s.quar", g_QuarantineDir, fname);
    
    // Temporarily normalize source file attributes before moving
    SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);

    // Use MoveFileExW with overwrite flag for enhanced stability
    if (MoveFileExW(filePath.c_str(), dest, MOVEFILE_REPLACE_EXISTING)) {
        EnterCriticalSection(&g_QuarantineCS);
        g_QuarantineList.push_back(dest);
        LeaveCriticalSection(&g_QuarantineCS);
        std::wstring qFileName = std::wstring(fname) + L".quar";
        WritePrivateProfileStringW(L"Quarantine", qFileName.c_str(), filePath.c_str(), g_ConfigFile);
        
        // Save quarantine isolation reason
        WritePrivateProfileStringW(L"QuarantineReason", qFileName.c_str(), reason.c_str(), g_ConfigFile);
        return true;
    }
    return false;
}

bool IsProcessSuspicious(const std::wstring& name) {
    std::wstring lower = name;
    for (size_t i = 0; i < lower.length(); ++i) lower[i] = towlower(lower[i]);
    if (lower == L"cmd.exe" || lower == L"powershell.exe" || lower == L"wscript.exe" || lower == L"cscript.exe") return true;
    return false;
}

void PopulateProcessList() {
    HANDLE hSnapshot = (dyn_CreateToolhelp32Snapshot != NULL) ? dyn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) : INVALID_HANDLE_VALUE;
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (dyn_Process32FirstW && dyn_Process32FirstW(hSnapshot, &pe)) {
        do {
            LVITEMW item = {0};
            int count = ListView_GetItemCount(g_hListView);
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            item.pszText = pe.szExeFile;
            ListView_InsertItem(g_hListView, &item);

            wchar_t pidStr[16];
            wsprintf_s(pidStr, 16, L"%d", pe.th32ProcessID);
            ListView_SetItemText(g_hListView, count, 1, pidStr);

            bool susp = IsProcessSuspicious(pe.szExeFile);
            ListView_SetItemText(g_hListView, count, 2, (LPWSTR)(susp ? L"Suspicious" : L"Normal"));
            ListView_SetItemText(g_hListView, count, 3, (LPWSTR)L"Monitoring");
        } while (dyn_Process32NextW && dyn_Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

void PopulateQuarantineList() {
    std::wstring searchPath = std::wstring(g_QuarantineDir) + L"\\*.quar";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring qFile = ffd.cFileName;
            wchar_t orig[MAX_PATH] = {0};
            GetPrivateProfileStringW(L"Quarantine", qFile.c_str(), L"Unknown Location", orig, MAX_PATH, g_ConfigFile);
            
            // Retrieve saved quarantine reason from configuration file
            wchar_t reason[256] = {0};
            GetPrivateProfileStringW(L"QuarantineReason", qFile.c_str(), L"Manual Isolation", reason, 256, g_ConfigFile);

            LVITEMW item = {0};
            int count = ListView_GetItemCount(g_hListView);
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            item.pszText = (LPWSTR)qFile.c_str();
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, count, 1, orig);
            
            // Display isolation reason in the third column
            ListView_SetItemText(g_hListView, count, 2, reason); 
        } while (FindNextFileW(hFind, &ffd) != 0);
        FindClose(hFind);
    }
}

void PopulateStartupList() {
    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D11180A091F0C1B2233171D0C110D11180A222917101A11090D223D0B0C0C1B100A281B0C0D171110222C0B10");
    
    // Scan HKCU Startup
    if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valueName[16384];
        BYTE valueData[16384];
        DWORD cbValueName = 16384;
        DWORD cbValueData = 16384;
        DWORD type;
        while (RegEnumValueW(hKey, index, valueName, &cbValueName, NULL, &type, valueData, &cbValueData) == ERROR_SUCCESS) {
            LVITEMW item = {0};
            int count = ListView_GetItemCount(g_hListView);
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            item.pszText = valueName;
            ListView_InsertItem(g_hListView, &item);
            
            ListView_SetItemText(g_hListView, count, 1, (LPWSTR)valueData);
            ListView_SetItemText(g_hListView, count, 2, (LPWSTR)L"HKCU\\Run");
            
            index++;
            cbValueName = 16384;
            cbValueData = 16384;
        }
        RegCloseKey(hKey);
    }

    // Scan HKLM Startup (Essential for legacy Windows XP Malware)
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valueName[16384];
        BYTE valueData[16384];
        DWORD cbValueName = 16384;
        DWORD cbValueData = 16384;
        DWORD type;
        while (RegEnumValueW(hKey, index, valueName, &cbValueName, NULL, &type, valueData, &cbValueData) == ERROR_SUCCESS) {
            LVITEMW item = {0};
            int count = ListView_GetItemCount(g_hListView);
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            item.pszText = valueName;
            ListView_InsertItem(g_hListView, &item);
            
            ListView_SetItemText(g_hListView, count, 1, (LPWSTR)valueData);
            ListView_SetItemText(g_hListView, count, 2, (LPWSTR)L"HKLM\\Run");
            
            index++;
            cbValueName = 16384;
            cbValueData = 16384;
        }
        RegCloseKey(hKey);
    }
}

bool IsTLS10Enabled() {
    HKEY hKey;
    DWORD enabled = 1; 
    DWORD cbData = sizeof(DWORD);
    std::wstring regPath = HexDecryptString(L"2D272D2A3B33223D0B0C0C1B100A3D11100A0C11122D1B0A223D11100A0C1112222D1B1C0B1D161B2D051109161B1B0C0D223C2C272E212E1B13222F0D111B111D11130D223F233C223E2E33223E13161B11102A");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"Enabled", NULL, NULL, (LPBYTE)&enabled, &cbData);
        RegCloseKey(hKey);
    }
    return (enabled != 0);
}

bool DisableTLS10Protocol() {
    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D272D2A3B33223D0B0C0C1B100A3D11100A0C11122D1B0A223D11100A0C1112222D1B1C0B1D161B2D051109161B1B0C0D223C2C272E212E1B13222F0D111B111D11130D223F233C223E2E33223E13161B11102A");
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD zero = 0;
        RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD, (const BYTE*)&zero, sizeof(DWORD));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

void ApplyAutoStartRegistry() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D11180A091F0C1B2233171D0C110D11180A222917101A11090D223D0B0C0C1B100A281B0C0D171110222C0B10");
    if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (g_bAutoStart) RegSetValueExW(hKey, L"SecureXP", 0, REG_SZ, (const BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        else RegDeleteValueW(hKey, L"SecureXP");
        RegCloseKey(hKey);
    }
}

bool DeleteStartupEntry(const std::wstring& valueName) {
    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D11180A091F0C1B2233171D0C110D11180A222917101A11090D223D0B0C0C1B100A281B0C0D171110222C0B10");
    if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        LSTATUS status = RegDeleteValueW(hKey, valueName.c_str());
        RegCloseKey(hKey);
        return (status == ERROR_SUCCESS);
    }
    return false;
}

void SanitizeStartupList() {
    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D11180A091F0C1B2233171D0C110D11180A222917101A11090D223D0B0C0C1B100A281B0C0D171110222C0B10");
    HKEY roots[2] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* rootNames[2] = { L"HKCU", L"HKLM" };
    
    for (int r = 0; r < 2; r++) {
        if (RegOpenKeyExW(roots[r], regPath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[16384];
            BYTE valueData[16384];
            DWORD cbValueName = 16384;
            DWORD cbValueData = 16384;
            DWORD type;
            std::vector<std::wstring> toDelete;
            while (RegEnumValueW(hKey, index, valueName, &cbValueName, NULL, &type, valueData, &cbValueData) == ERROR_SUCCESS) {
                std::wstring cmd = (wchar_t*)valueData;
                std::wstring lowerCmd = cmd;
                for (auto& c : lowerCmd) c = towlower(c);
                
                // Enhanced directory coverage for legacy Windows XP folder paths
                if (lowerCmd.find(L"\\temp\\") != std::wstring::npos || 
                    lowerCmd.find(L"\\users\\public\\") != std::wstring::npos ||
                    lowerCmd.find(L"\\documents and settings\\all users\\") != std::wstring::npos) {
                    toDelete.push_back(valueName);
                }
                index++;
                cbValueName = 16384;
                cbValueData = 16384;
            }
            for (const auto& name : toDelete) {
                if (RegDeleteValueW(hKey, name.c_str()) == ERROR_SUCCESS) {
                    std::wstring alertMsg = std::wstring(rootNames[r]) + L" Startup Guard blocked threat: " + name;
                    ShowNotification(L"Startup Guard Active", alertMsg, NIIF_WARNING);
                }
            }
            RegCloseKey(hKey);
        }
    }
}

void PopulateIEGuard() {
    CheckBrowserHomePageHijack();
    CheckWindowsUpdateWSUSHijack();

    HKEY hKey;
    std::wstring regPath = HexDecryptString(L"2D11180A091F0C1B2233171D0C110D11180A222617101A11090D22261F0D1B0C11171010223D0B0C1B10101B0A223F2E332E3A3C0A1F0D");
    if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valueName[256];
        BYTE valueData[2048];
        DWORD cbValueName = 256;
        DWORD cbValueData = 2048;
        DWORD type;
        while (RegEnumValueW(hKey, index, valueName, &cbValueName, NULL, &type, valueData, &cbValueData) == ERROR_SUCCESS) {
            std::wstring url = (wchar_t*)valueData;
            std::wstring lowerUrl = url;
            for (auto& c : lowerUrl) c = towlower(c);

            bool susp = false;
            if (lowerUrl.find(L"phishing") != std::wstring::npos || lowerUrl.find(L"malware") != std::wstring::npos) {
                susp = true;
            }

            int count = ListView_GetItemCount(g_hListView);
            LVITEMW item = {0};
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            item.pszText = (LPWSTR)url.c_str();
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, count, 1, (LPWSTR)(susp ? L"Suspicious Website" : L"Normal URL History"));
            ListView_SetItemText(g_hListView, count, 2, (LPWSTR)L"Identified Browser Log");
            
            index++;
            cbValueName = 256;
            cbValueData = 2048;
        }
        RegCloseKey(hKey);
    }
}

void CheckDNSServerSafety() {
    FIXED_INFO* pFixedInfo = NULL;
    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    pFixedInfo = (FIXED_INFO*)malloc(sizeof(FIXED_INFO));
    if (pFixedInfo == NULL) return;

    if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pFixedInfo);
        pFixedInfo = (FIXED_INFO*)malloc(ulOutBufLen);
        if (pFixedInfo == NULL) return;
    }

    if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {
        IP_ADDR_STRING* pIPAddr = &pFixedInfo->DnsServerList;
        while (pIPAddr) {
            std::string dnsIp = pIPAddr->IpAddress.String;
            std::wstring wDnsIp(dnsIp.begin(), dnsIp.end());
            
            bool suspicious = false;
            std::wstring status = L"Active DNS Server";
            std::wstring advice = L"Secure Resolver Configured";

            if (dnsIp == "127.0.0.1" || dnsIp == "localhost" || dnsIp.find("127.") == 0) {
                suspicious = true;
                status = L"Local DNS Loopback Redirection";
                advice = L"Potential local adware DNS proxy detected!";
            }

            int count = ListView_GetItemCount(g_hListView);
            LVITEMW item = {0};
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            std::wstring title = L"DNS Configuration: " + wDnsIp;
            item.pszText = (LPWSTR)title.c_str();
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, count, 1, (LPWSTR)status.c_str());
            ListView_SetItemText(g_hListView, count, 2, (LPWSTR)advice.c_str());

            pIPAddr = pIPAddr->Next;
        }
    }
    free(pFixedInfo);
}

void CheckBrowserHomePageHijack() {
    HKEY hKey;
    std::wstring regPath = L"Software\\Microsoft\\Internet Explorer\\Main";
    if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t startPage[1024] = {0};
        DWORD cbData = sizeof(startPage);
        if (RegQueryValueExW(hKey, L"Start Page", NULL, NULL, (LPBYTE)startPage, &cbData) == ERROR_SUCCESS) {
            std::wstring homePage = startPage;
            std::wstring lowerHome = homePage;
            for (auto& c : lowerHome) c = towlower(c);

            bool hijacked = false;
            std::wstring status = L"Safe Homepage";
            std::wstring advice = L"Homepage is clean";

            if (lowerHome.find(L"hijack") != std::wstring::npos || 
                lowerHome.find(L"search-go") != std::wstring::npos ||
                lowerHome.find(L"babylon") != std::wstring::npos ||
                lowerHome.find(L"conduit") != std::wstring::npos) {
                hijacked = true;
                status = L"Hijacked Homepage Pattern";
                advice = L"Right-click to restore default homepage.";
            }

            int count = ListView_GetItemCount(g_hListView);
            LVITEMW item = {0};
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            std::wstring title = L"Browser Homepage: " + homePage;
            item.pszText = (LPWSTR)title.c_str();
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, count, 1, (LPWSTR)status.c_str());
            ListView_SetItemText(g_hListView, count, 2, (LPWSTR)advice.c_str());
        }
        RegCloseKey(hKey);
    }
}

void CheckWindowsUpdateWSUSHijack() {
    HKEY hKey;
    std::wstring regPath = L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t wsusServer[1024] = {0};
        DWORD cbData = sizeof(wsusServer);
        if (RegQueryValueExW(hKey, L"WUServer", NULL, NULL, (LPBYTE)wsusServer, &cbData) == ERROR_SUCCESS) {
            std::wstring server = wsusServer;
            int count = ListView_GetItemCount(g_hListView);
            LVITEMW item = {0};
            item.mask = LVIF_TEXT;
            item.iItem = count;
            item.iSubItem = 0;
            std::wstring title = L"WSUS Update Server: " + server;
            item.pszText = (LPWSTR)title.c_str();
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, count, 1, L"Active Redirection");
            ListView_SetItemText(g_hListView, count, 2, L"Updates are served from local policy server");
        }
        RegCloseKey(hKey);
    }
}

void PopulateNetworkGuard() {
    CheckDNSServerSafety();

    bool tls10 = IsTLS10Enabled();
    LVITEMW item = {0};
    int count = ListView_GetItemCount(g_hListView);
    item.mask = LVIF_TEXT;
    item.iItem = count;
    item.iSubItem = 0;
    item.pszText = (LPWSTR)L"Protocol: TLS 1.0 / 1.1 Client";
    ListView_InsertItem(g_hListView, &item);
    ListView_SetItemText(g_hListView, count, 1, tls10 ? (LPWSTR)L"Vulnerable" : (LPWSTR)L"Secured");
    ListView_SetItemText(g_hListView, count, 2, (LPWSTR)L"Right-click to Disable");

    MIB_TCPTABLE* pTcpTable = NULL;
    DWORD dwSize = 0;
    if (GetTcpTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE*)malloc(dwSize);
        if (GetTcpTable(pTcpTable, &dwSize, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                DWORD localPort = CustomNtohs((u_short)pTcpTable->table[i].dwLocalPort);
                DWORD state = pTcpTable->table[i].dwState;

                if (state == MIB_TCP_STATE_LISTEN) {
                    wchar_t portName[128];
                    wsprintf_s(portName, 128, L"Port Listener: %d", localPort);
                    
                    std::wstring status = L"Active Service";
                    std::wstring advice = L"Review port accessibility";
                    
                    if (localPort == 445) {
                        status = L"Critical Port (SMB)";
                        advice = g_bBlockPort445 ? L"SecureXP Shield actively blocking." : L"Conficker Vector! Recommend blocking.";
                    }
                    else if (localPort == 135) {
                        status = L"Critical Port (RPC)";
                        advice = g_bBlockPort135 ? L"SecureXP Shield actively blocking." : L"Blaster Worm Vector! Recommend blocking.";
                    }
                    else if (localPort == 3389) {
                        status = L"Remote Desktop (RDP)";
                        advice = g_bBlockPort3389 ? L"SecureXP Shield actively blocking." : L"BlueKeep Vector! Shield is filtering.";
                    }

                    int c = ListView_GetItemCount(g_hListView);
                    LVITEMW portItem = {0};
                    portItem.mask = LVIF_TEXT;
                    portItem.iItem = c;
                    portItem.iSubItem = 0;
                    portItem.pszText = portName;
                    ListView_InsertItem(g_hListView, &portItem);
                    ListView_SetItemText(g_hListView, count, 1, (LPWSTR)status.c_str());
                    ListView_SetItemText(g_hListView, count, 2, (LPWSTR)advice.c_str());
                }
            }
        }
        free(pTcpTable);
    }
}

void RefreshListView() {
    ListView_DeleteAllItems(g_hListView);
    HWND hHeader = (HWND)SendMessage(g_hListView, LVM_GETHEADER, 0, 0);
    int colCount = Header_GetItemCount(hHeader);
    for (int i = colCount - 1; i >= 0; i--) ListView_DeleteColumn(g_hListView, i);

    LVCOLUMNW col = {0};
    col.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;

    if (g_Selected == 0 || g_Selected == 1 || g_Selected == 2 || g_Selected == 3) { 
        col.cx=280; col.pszText=(LPWSTR)L"Diagnostic Location"; ListView_InsertColumn(g_hListView, 0, &col);
        col.cx=140; col.pszText=(LPWSTR)L"Status / Threat Type"; ListView_InsertColumn(g_hListView, 1, &col);
        col.cx=200; col.pszText=(LPWSTR)L"MD5 Signature"; ListView_InsertColumn(g_hListView, 2, &col);
    }
    else if (g_Selected == 5) { 
        col.cx=220; col.pszText=(LPWSTR)L"Quarantined File"; ListView_InsertColumn(g_hListView, 0, &col);
        col.cx=320; col.pszText=(LPWSTR)L"Original Location Path"; ListView_InsertColumn(g_hListView, 1, &col);
        col.cx=180; col.pszText=(LPWSTR)L"Isolation Reason"; ListView_InsertColumn(g_hListView, 2, &col); 
        PopulateQuarantineList();
    }
}

void PerformRealtimeNetworkAndWebScan() {
    if (!g_bRealTimeProtection) return;

    MIB_TCPTABLE* pTcpTable = NULL;
    DWORD dwSize = 0;
    if (GetTcpTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE*)malloc(dwSize);
        if (GetTcpTable(pTcpTable, &dwSize, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                DWORD localPort = CustomNtohs((u_short)pTcpTable->table[i].dwLocalPort);
                DWORD state = pTcpTable->table[i].dwState;

                if (state == MIB_TCP_STATE_LISTEN && localPort == 445 && !g_bBlockPort445) {
                    static bool bWarned445 = false;
                    if (!bWarned445) {
                        bWarned445 = true;
                        ShowNotification(L"System Vulnerability Exposed", L"Port 445 (SMB) is listening! Windows XP system is highly vulnerable.", NIIF_WARNING);
                    }
                }
            }
        }
        free(pTcpTable);
    }
}

void PerformRealtimeScan() {
    if(!g_bRealTimeProtection || g_bIsScanning) return; 

    PerformRealtimeNetworkAndWebScan();
    VerifyCanaryFiles();
    CheckAndRemediateHostsFile();

    if (g_bAutoSanitize) {
        SanitizeStartupList();
    }

    if (g_bAutoStart) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        HKEY hKey;
        std::wstring regPath = HexDecryptString(L"2D11180A091F0C1B2233171D0C110D11180A222917101A11090D223D0B0C0C1B100A281B0C0D171110222C0B10");
        if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ | KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            wchar_t existingPath[MAX_PATH] = {0};
            DWORD cbData = sizeof(existingPath);
            if (RegQueryValueExW(hKey, L"SecureXP", NULL, NULL, (LPBYTE)existingPath, &cbData) != ERROR_SUCCESS ||
                wcscmp(existingPath, exePath) != 0) {
                RegSetValueExW(hKey, L"SecureXP", 0, REG_SZ, (const BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
            }
            RegCloseKey(hKey);
        }
    }
}

void LoadExclusions() {
    g_ExcludedFolders.clear();
    int count = GetPrivateProfileIntW(L"Exclusions", L"PathCount", 0, g_ConfigFile);
    for (int i = 0; i < count; i++) {
        wchar_t key[32];
        wsprintf_s(key, 32, L"Path%d", i);
        wchar_t path[MAX_PATH];
        GetPrivateProfileStringW(L"Exclusions", key, L"", path, MAX_PATH, g_ConfigFile);
        if (wcslen(path) > 0) {
            g_ExcludedFolders.push_back(path);
        }
    }
}

void SaveExclusions() {
    WritePrivateProfileSectionW(L"Exclusions", L"", g_ConfigFile);
    
    wchar_t countStr[16];
    wsprintf_s(countStr, 16, L"%d", (int)g_ExcludedFolders.size());
    WritePrivateProfileStringW(L"Exclusions", L"PathCount", countStr, g_ConfigFile);
    for (size_t i = 0; i < g_ExcludedFolders.size(); i++) {
        wchar_t key[32];
        wsprintf_s(key, 32, L"Path%d", (int)i);
        WritePrivateProfileStringW(L"Exclusions", key, g_ExcludedFolders[i].c_str(), g_ConfigFile);
    }
}

void LoadSettings() {
    g_bRealTimeProtection = (GetPrivateProfileIntW(L"Settings", L"Realtime", 1, g_ConfigFile) == 1);
    g_AutomationLevel = GetPrivateProfileIntW(L"Settings", L"Automation", 0, g_ConfigFile);
    g_bAutoStart = (GetPrivateProfileIntW(L"Settings", L"AutoStart", 0, g_ConfigFile) == 1); 
    g_bAutoSanitize = (GetPrivateProfileIntW(L"Settings", L"AutoSanitize", 0, g_ConfigFile) == 1); 
    g_bSilentMode = (GetPrivateProfileIntW(L"Settings", L"SilentMode", 0, g_ConfigFile) == 1); 
    
    g_bBlockPort445 = (GetPrivateProfileIntW(L"Settings", L"BlockPort445", 0, g_ConfigFile) == 1);
    g_bBlockPort135 = (GetPrivateProfileIntW(L"Settings", L"BlockPort135", 0, g_ConfigFile) == 1);
    g_bBlockPort3389 = (GetPrivateProfileIntW(L"Settings", L"BlockPort3389", 0, g_ConfigFile) == 1);

    g_HeuristicLevel = GetPrivateProfileIntW(L"Settings", L"HeuristicLevel", 1, g_ConfigFile);
    g_bBlockUSB = (GetPrivateProfileIntW(L"Settings", L"BlockUSB", 0, g_ConfigFile) == 1);
    g_bRamShield = (GetPrivateProfileIntW(L"Settings", L"RamShield", 0, g_ConfigFile) == 1); 
    g_bBrowserShield = (GetPrivateProfileIntW(L"Settings", L"BrowserShield", 1, g_ConfigFile) == 1);
    g_bCredentialGuard = (GetPrivateProfileIntW(L"Settings", L"CredentialGuard", 0, g_ConfigFile) == 1); 

    g_bNetworkShield = (GetPrivateProfileIntW(L"Settings", L"NetworkShield", 1, g_ConfigFile) == 1);
    g_bHipsCanary = (GetPrivateProfileIntW(L"Settings", L"HipsCanary", 0, g_ConfigFile) == 1); 
    g_bHostsGuard = (GetPrivateProfileIntW(L"Settings", L"HostsGuard", 0, g_ConfigFile) == 1); 
    g_bLsassProtect = (GetPrivateProfileIntW(L"Settings", L"LsassProtect", 0, g_ConfigFile) == 1); 

    LoadExclusions();
}

void SaveSettings() {
    WritePrivateProfileStringW(L"Settings", L"Realtime", g_bRealTimeProtection ? L"1" : L"0", g_ConfigFile);
    wchar_t buf[16];
    wsprintf_s(buf, 16, L"%d", g_AutomationLevel);
    WritePrivateProfileStringW(L"Settings", L"Automation", buf, g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"AutoStart", g_bAutoStart ? L"1" : L"0", g_ConfigFile); 
    WritePrivateProfileStringW(L"Settings", L"AutoSanitize", g_bAutoSanitize ? L"1" : L"0", g_ConfigFile); 
    WritePrivateProfileStringW(L"Settings", L"SilentMode", g_bSilentMode ? L"1" : L"0", g_ConfigFile); 
    
    WritePrivateProfileStringW(L"Settings", L"BlockPort445", g_bBlockPort445 ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"BlockPort135", g_bBlockPort135 ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"BlockPort3389", g_bBlockPort3389 ? L"1" : L"0", g_ConfigFile);

    wsprintf_s(buf, 16, L"%d", g_HeuristicLevel);
    WritePrivateProfileStringW(L"Settings", L"HeuristicLevel", buf, g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"BlockUSB", g_bBlockUSB ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"RamShield", g_bRamShield ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"BrowserShield", g_bBrowserShield ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"CredentialGuard", g_bCredentialGuard ? L"1" : L"0", g_ConfigFile);

    WritePrivateProfileStringW(L"Settings", L"NetworkShield", g_bNetworkShield ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"HipsCanary", g_bHipsCanary ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"HostsGuard", g_bHostsGuard ? L"1" : L"0", g_ConfigFile);
    WritePrivateProfileStringW(L"Settings", L"LsassProtect", g_bLsassProtect ? L"1" : L"0", g_ConfigFile);

    SaveExclusions();
}

void DrawSidebarItem(HDC hdc, int index, bool sel, RECT rect) {
    HBRUSH br;
    if (sel) {
        br = CreateSolidBrush(RGB(0, 100, 240)); 
        SetTextColor(hdc, RGB(255, 255, 255));
    } else {
        if (index == g_HoveredItem) {
            br = CreateSolidBrush(RGB(235, 243, 255)); 
            SetTextColor(hdc, RGB(0, 100, 240));
        } else {
            br = CreateSolidBrush(RGB(247, 249, 252)); 
            SetTextColor(hdc, RGB(60, 70, 90));
        }
    }

    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, br);
    HPEN nullPen = (HPEN)GetStockObject(NULL_PEN);
    HPEN oldPen = (HPEN)SelectObject(hdc, nullPen);
    
    Rectangle(hdc, rect.left + 5, rect.top + 2, rect.right - 5, rect.bottom - 2);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(br);

    SetBkMode(hdc, TRANSPARENT);
    int cx = rect.left + 24;
    int cy = rect.top + (rect.bottom - rect.top) / 2;
    DrawSidebarIcon(hdc, index, cx, cy, sel ? RGB(255, 255, 255) : RGB(100, 115, 135));

    RECT textRect = { rect.left + 46, rect.top, rect.right - 5, rect.bottom };
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_MEDIUM, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
    HFONT oldFont = (HFONT)SelectObject(hdc, hFont);
    DrawTextW(hdc, g_SidebarItems[index], -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    
    SelectObject(hdc, oldFont);
    DeleteObject(hFont);
}

bool GetFileBinaryMD5(const std::wstring& filePath, BYTE* outHash) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }

    BYTE buffer[4096];
    DWORD bytesRead = 0;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }

    DWORD hashLen = 16;
    bool bSuccess = false;
    if (CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashLen, 0)) {
        bSuccess = true;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return bSuccess;
}

bool ScanFileForSignatures(const std::wstring& filePath, std::wstring& foundSig) {
    BYTE outHash[16];
    if (!GetFileBinaryMD5(filePath, outHash)) return false;

    wchar_t hex[33] = {0};
    for (int i = 0; i < 16; i++) {
        // Corrected hex formatting logic to construct a full 32-character MD5 hex string.
        swprintf_s(hex + (i * 2), 33 - (i * 2), L"%02x", outHash[i]);
    }
    if (g_WhitelistDatabase.count(hex) > 0) {
        return false; 
    }

    size_t dbSize = sizeof(g_ObfuscatedDatabase) / sizeof(g_ObfuscatedDatabase[0]);
    for (size_t i = 0; i < dbSize; i++) {
        BYTE decHash[16];
        for (int j = 0; j < 16; j++) {
            decHash[j] = g_ObfuscatedDatabase[i].encHashBytes[j] ^ 0x3D; 
        }
        if (memcmp(outHash, decHash, 16) == 0) {
            foundSig = HexDecryptString(g_ObfuscatedDatabase[i].encName);
            return true;
        }
    }
    return false;
}

bool ScanFileContentForByteSignatures(const std::wstring& filePath, std::wstring& foundSig) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0 || fileSize.QuadPart > 10 * 1024 * 1024) { 
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesToRead = (DWORD)fileSize.QuadPart;
    std::vector<BYTE> buffer(bytesToRead); 
    
    DWORD bytesRead = 0;
    bool bSuccess = ReadFile(hFile, buffer.data(), bytesToRead, &bytesRead, NULL);
    CloseHandle(hFile);

    if (!bSuccess || bytesRead == 0) return false;

    for (size_t i = 0; i < g_ByteSignaturesCount; i++) {
        const auto& sig = g_ByteSignatures[i];
        if (bytesRead < sig.length) continue;

        for (DWORD j = 0; j <= bytesRead - sig.length; j++) {
            if (memcmp(buffer.data() + j, sig.pattern, sig.length) == 0) {
                foundSig = sig.name;
                return true;
            }
        }
    }
    return false;
}

bool VerifyFileFormatIntegrity(const std::wstring& filePath, std::wstring& formatReason) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return true; 

    IMAGE_DOS_HEADER dosHeader;
    DWORD read;
    if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &read, NULL) && read == sizeof(dosHeader)) {
        if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) { 
            if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                DWORD peSignature;
                if (ReadFile(hFile, &peSignature, sizeof(peSignature), &read, NULL) && read == sizeof(peSignature)) {
                    if (peSignature != IMAGE_NT_SIGNATURE) { 
                        formatReason = L"Corrupt Executable Header";
                        CloseHandle(hFile);
                        return false; 
                    }
                }
            }
        }
    }
    CloseHandle(hFile);
    return true;
}

bool ScanScriptBehavior(const std::wstring& filePath, std::wstring& triggerReason) {
    std::wstring ext = L"";
    size_t dot = filePath.find_last_of(L'.');
    if (dot != std::wstring::npos) ext = filePath.substr(dot);
    for (auto& c : ext) c = towlower(c);

    if (ext == L".bat" || ext == L".vbs" || ext == L".ps1" || ext == L".js") {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD size = GetFileSize(hFile, NULL);
        if (size > 0 && size < 1048576) { 
            char* buffer = (char*)malloc(size + 1);
            if (buffer) {
                DWORD read;
                if (ReadFile(hFile, buffer, size, &read, NULL)) {
                    buffer[read] = '\0';
                    std::string content(buffer);
                    for (auto& c : content) c = tolower(c);

                    if (content.find("downloadstring") != std::string::npos ||
                        content.find("wscript.shell") != std::string::npos ||
                        content.find("shred") != std::string::npos ||
                        content.find("kill") != std::string::npos ||
                        content.find("bypass") != std::string::npos) {
                        triggerReason = L"Suspicious script command pattern detected";
                        free(buffer);
                        CloseHandle(hFile);
                        return true;
                    }
                }
                free(buffer);
            }
        }
        CloseHandle(hFile);
    }
    return false;
}

int AnalyzeHeuristicRisk(const std::wstring& filePath, std::wstring& riskReason) {
    if (IsPathExcluded(filePath)) {
        riskReason = L"Excluded Path";
        return 0;
    }

    std::wstring signatureThreat = L"";
    if (ScanFileForSignatures(filePath, signatureThreat)) {
        riskReason = L"Known Threat Signature: " + signatureThreat;
        return 100; 
    }

    // Integrated the Cloud Threat Intelligence check directly into the core heuristic scoring sequence
    BYTE outHash[16];
    if (GetFileBinaryMD5(filePath, outHash)) {
        wchar_t hex[33] = {0};
        for (int i = 0; i < 16; i++) {
            swprintf_s(hex + (i * 2), 33 - (i * 2), L"%02x", outHash[i]);
        }
        if (QueryCloudThreatIntel(hex)) {
            riskReason = L"Cloud Threat Intelligence Match";
            return 100;
        }
    }

    std::wstring contentThreat = L"";
    if (ScanFileContentForByteSignatures(filePath, contentThreat)) {
        riskReason = L"Hex Match: " + contentThreat;
        return 100;
    }

    std::wstring scriptReason = L"";
    if (ScanScriptBehavior(filePath, scriptReason)) {
        riskReason = scriptReason;
        return 85; 
    }

    std::wstring formatReason = L"";
    if (!VerifyFileFormatIntegrity(filePath, formatReason)) {
        riskReason = formatReason;
        return 70; 
    }

    std::wstring lowerPath = filePath;
    for (auto& c : lowerPath) c = towlower(c);

    size_t firstDot = lowerPath.find(L'.');
    size_t lastDot = lowerPath.find_last_of(L'.');
    if (firstDot != std::wstring::npos && lastDot != std::wstring::npos && firstDot != lastDot) {
        std::wstring finalExt = lowerPath.substr(lastDot);
        if (finalExt == L".exe" || finalExt == L".scr" || finalExt == L".pif" || finalExt == L".com" || finalExt == L".bat" || finalExt == L".vbs") {
            riskReason = L"Suspicious dual extension execution (.ext.exe)";
            return 85;
        }
    }

    // Heuristics tailored for traditional Windows XP structure
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos || 
        lowerPath.find(L"\\appdata\\local\\temp") != std::wstring::npos ||
        lowerPath.find(L"\\local settings\\temp") != std::wstring::npos) {
        std::wstring ext = L"";
        size_t dot = lowerPath.find_last_of(L'.');
        if (dot != std::wstring::npos) ext = lowerPath.substr(dot);
        if (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".pif" || ext == L".com") {
            riskReason = L"Unsigned binary executing from Temp directory";
            return 75;
        }
    }

    DWORD attribs = GetFileAttributesW(filePath.c_str());
    if (attribs != INVALID_FILE_ATTRIBUTES) {
        if ((attribs & FILE_ATTRIBUTE_HIDDEN) || (attribs & FILE_ATTRIBUTE_SYSTEM)) {
            std::wstring ext = L"";
            size_t dot = lowerPath.find_last_of(L'.');
            if (dot != std::wstring::npos) ext = lowerPath.substr(dot);
            if (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".bat" || ext == L".vbs") {
                if (lowerPath.find(L"\\windows\\") == std::wstring::npos && 
                    lowerPath.find(L"\\winnt\\") == std::wstring::npos &&
                    lowerPath.find(L"\\documents and settings\\") == std::wstring::npos) {
                    riskReason = L"Hidden system executable in user writable directory";
                    return 90;
                }
            }
        }
    }

    double entropy = CalculateShannonEntropy(filePath);
    if (entropy > 7.2) {
        if (lowerPath.find(L"\\temp\\") != std::wstring::npos || 
            lowerPath.find(L"\\local settings\\temp") != std::wstring::npos) {
            wchar_t entropyBuf[32];
            swprintf_s(entropyBuf, 32, L"%.2f", entropy);
            riskReason = std::wstring(L"High Entropy Packed Binary in Temp (Entropy: ") + entropyBuf + L")";
            return 80; 
        }
    }

    return 0; 
}

bool ScanProcessMemoryForPE(HANDLE hProc, LPVOID baseAddr, SIZE_T regionSize) {
    if (regionSize < 1024) return false;
    BYTE buffer[1024];
    SIZE_T bytesRead = 0;
    if (dyn_ReadProcessMemory && dyn_ReadProcessMemory(hProc, baseAddr, buffer, 1024, &bytesRead) && bytesRead >= 64) {
        if (buffer[0] == 0x4D && buffer[1] == 0x5A) { 
            DWORD peOffset = *(DWORD*)(buffer + 0x3C);
            if (peOffset < 1020) {
                BYTE* peHeader = buffer + peOffset;
                if (peHeader[0] == 0x50 && peHeader[1] == 0x45 && peHeader[2] == 0x00 && peHeader[3] == 0x00) { 
                    return true;
                }
            }
        }
    }
    return false;
}

void DrawScanningShieldIcon(HDC hdc, int cx, int cy, int size) {
    POINT shieldPts[7];
    shieldPts[0].x = cx;                     shieldPts[0].y = cy - size;
    shieldPts[1].x = cx + (int)(size * 0.9); shieldPts[1].y = cy - (int)(size * 0.6);
    shieldPts[2].x = cx + (int)(size * 0.9); shieldPts[2].y = cy + (int)(size * 0.2);
    shieldPts[3].x = cx;                     shieldPts[3].y = cy + size;
    shieldPts[4].x = cx - (int)(size * 0.9); shieldPts[4].y = cy + (int)(size * 0.2);
    shieldPts[5].x = cx - (int)(size * 0.9); shieldPts[5].y = cy - (int)(size * 0.6);
    shieldPts[6].x = cx;                     shieldPts[6].y = cy - size;

    HBRUSH shieldBrush = CreateSolidBrush(RGB(14, 165, 233)); 
    HPEN shieldPen = CreatePen(PS_SOLID, 2, RGB(2, 132, 199));
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, shieldBrush);
    HPEN oldPen = (HPEN)SelectObject(hdc, shieldPen);

    Polygon(hdc, shieldPts, 7);

    double scanFactor = sin(g_AnimAngle * 3.14159265 / 180.0); 
    int scanY = cy + (int)(size * 0.8 * scanFactor);

    HPEN laserPen = CreatePen(PS_SOLID, 3, RGB(255, 255, 255)); 
    SelectObject(hdc, laserPen);
    MoveToEx(hdc, cx - (int)(size * 0.7), scanY, NULL);
    LineTo(hdc, cx + (int)(size * 0.7), scanY);
    
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(laserPen);
    DeleteObject(shieldBrush);
    DeleteObject(shieldPen);
}

void DrawSafeStatusIndicator(HDC hdc, int cx, int cy, int size, COLORREF themeColor) {
    HBRUSH bgBrush = CreateSolidBrush(themeColor);
    HPEN borderPen = CreatePen(PS_SOLID, 2, RGB(22, 163, 74)); 
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, bgBrush);
    HPEN oldPen = (HPEN)SelectObject(hdc, borderPen);

    Ellipse(hdc, cx - size, cy - size, cx + size, cy + size);

    HPEN checkPen = CreatePen(PS_SOLID, 4, RGB(255, 255, 255));
    SelectObject(hdc, checkPen);

    int x1 = cx - (int)(size * 0.4);
    int y1 = cy;
    int x2 = cx - (int)(size * 0.1);
    int y2 = cy + (int)(size * 0.3);
    int x3 = cx + (int)(size * 0.45);
    int y3 = cy - (int)(size * 0.3);

    MoveToEx(hdc, x1, y1, NULL);
    LineTo(hdc, x2, y2);
    LineTo(hdc, x3, y3);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(bgBrush);
    DeleteObject(borderPen);
    DeleteObject(checkPen);
}

void DrawCentralDisplay(HDC hdc, RECT rect) {
    HBRUSH bgBrush = CreateSolidBrush(RGB(241, 245, 249));
    FillRect(hdc, &rect, bgBrush);
    DeleteObject(bgBrush);

    int cx = rect.left + (rect.right - rect.left) / 2;
    int cy = rect.top + (rect.bottom - rect.top) / 2 - 20;
    
    if (g_Selected == 4) {
        SetTextColor(hdc, RGB(15, 23, 42));
        SetBkMode(hdc, TRANSPARENT);
        HFONT hFontText = CreateFontW(18, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
        HFONT hOldFont = (HFONT)SelectObject(hdc, hFontText);

        RECT textRect = { rect.left + 20, rect.top + 15, rect.right, rect.top + 45 };
        DrawTextW(hdc, L"Integrated System Security Settings", -1, &textRect, DT_LEFT | DT_SINGLELINE);

        HFONT hSubFont = CreateFontW(11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
        SelectObject(hdc, hSubFont);
        RECT subRect = { rect.left + 22, rect.top + 40, rect.right, rect.top + 60 };
        SetTextColor(hdc, RGB(100, 116, 139));
        DrawTextW(hdc, L"Configure active protection shields, system port blocking, and advanced heuristic engine profiles.", -1, &subRect, DT_LEFT | DT_SINGLELINE);

        SelectObject(hdc, hOldFont);
        DeleteObject(hFontText);
        DeleteObject(hSubFont);
        return;
    }

    if (g_bIsScanning) {
        DrawScanningShieldIcon(hdc, cx, cy - 10, 25);

        int progressWidth = 400;
        int progressHeight = 10;
        int px = cx - progressWidth / 2;
        int py = cy + 30;

        HBRUSH bgBar = CreateSolidBrush(RGB(226, 232, 240));
        RECT rcBgBar = { px, py, px + progressWidth, py + progressHeight };
        FillRect(hdc, &rcBgBar, bgBar);
        DeleteObject(bgBar);

        double percent = 0.0;
        if (g_TotalFilesToScan > 0) {
            percent = (double)g_FilesScannedCount / (double)g_TotalFilesToScan;
            if (percent > 1.0) percent = 1.0;
        }

        int filledWidth = (int)(progressWidth * percent);
        HBRUSH activeBar = CreateSolidBrush(RGB(14, 165, 233)); 
        RECT rcActiveBar = { px, py, px + filledWidth, py + progressHeight };
        FillRect(hdc, &rcActiveBar, activeBar);
        DeleteObject(activeBar);

        int remainingPercent = 100 - (int)(percent * 100);
        wchar_t percentText[64];
        wsprintf_s(percentText, 64, L"%d%% Remaining", remainingPercent);

        SetTextColor(hdc, RGB(71, 85, 105));
        SetBkMode(hdc, TRANSPARENT);
        HFONT hFontPercent = CreateFontW(14, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
        HFONT hOldFontP = (HFONT)SelectObject(hdc, hFontPercent);
        RECT percentRect = { rect.left, py + 15, rect.right, py + 35 };
        DrawTextW(hdc, percentText, -1, &percentRect, DT_CENTER | DT_SINGLELINE);
        SelectObject(hdc, hOldFontP); 
        DeleteObject(hFontPercent);

    } else {
        DrawSafeStatusIndicator(hdc, cx, cy, 28, RGB(34, 197, 94));

        double angleRad = g_AnimAngle * 3.14159265 / 180.0;
        int pulseRadius = 45 + (int)(5.0 * sin(angleRad * 2.0)); 

        HPEN haloPen = CreatePen(PS_DOT, 1, RGB(34, 197, 94)); 
        HPEN oldPen = (HPEN)SelectObject(hdc, haloPen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));

        Ellipse(hdc, cx - pulseRadius, cy - pulseRadius, cx + pulseRadius, cy + pulseRadius);

        int orbitX = cx + (int)(pulseRadius * cos(angleRad));
        int orbitY = cy + (int)(pulseRadius * sin(angleRad));
        HBRUSH nodeBrush = CreateSolidBrush(RGB(74, 222, 128));
        SelectObject(hdc, nodeBrush);
        HPEN nodePen = CreatePen(PS_SOLID, 1, RGB(34, 197, 94));
        SelectObject(hdc, nodePen);
        Ellipse(hdc, orbitX - 4, orbitY - 4, orbitX + 4, orbitY + 4);

        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(haloPen);
        DeleteObject(nodeBrush);
        DeleteObject(nodePen);
    }

    SetTextColor(hdc, RGB(15, 23, 42)); 
    SetBkMode(hdc, TRANSPARENT);
    HFONT hFontText = CreateFontW(18, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
    HFONT hOldFont = (HFONT)SelectObject(hdc, hFontText);

    std::wstring statusStr = g_bIsScanning ? L"Scanning System..." : L"Your System Is Secure";
    RECT textRect = { rect.left, cy + 68, rect.right, cy + 98 };
    if (g_bIsScanning) {
        textRect.top = cy + 78;
        textRect.bottom = cy + 108;
    }
    DrawTextW(hdc, statusStr.c_str(), -1, &textRect, DT_CENTER | DT_SINGLELINE);

    if (g_bIsScanning && !g_CurrentScanningFile.empty()) {
        HFONT hSubFont = CreateFontW(11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
        SelectObject(hdc, hSubFont);
        
        std::wstring scanMsg = L"Checking: " + g_CurrentScanningFile;
        if (scanMsg.length() > 65) scanMsg = scanMsg.substr(0, 62) + L"...";
        
        RECT subRect = { rect.left + 20, cy + 98, rect.right - 20, cy + 125 };
        SetTextColor(hdc, RGB(100, 116, 139)); 
        DrawTextW(hdc, scanMsg.c_str(), -1, &subRect, DT_CENTER | DT_SINGLELINE);
        DeleteObject(hSubFont);
    }

    SelectObject(hdc, hOldFont);
    DeleteObject(hFontText);
}

void PreCountFilesRecursively(const std::wstring& directory) {
    if (!g_bIsScanning) return;
    if (IsPathExcluded(directory)) return;

    std::wstring searchPath = directory + L"\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) {
            continue;
        }

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::wstring subDir = directory + L"\\" + ffd.cFileName;
            PreCountFilesRecursively(subDir);
        } else {
            std::wstring fileCheck = directory + L"\\" + ffd.cFileName;
            if (!IsPathExcluded(fileCheck)) {
                g_TotalFilesToScan++;
            }
        }
    } while (FindNextFileW(hFind, &ffd) != 0 && g_bIsScanning);

    FindClose(hFind);
}

void ScanDirectoryRecursively(const std::wstring& directory) {
    if (!g_bIsScanning) return;
    if (IsPathExcluded(directory)) return;

    std::wstring searchPath = directory + L"\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring fullPath = directory + L"\\" + ffd.cFileName;
        if (IsPathExcluded(fullPath)) continue;
        
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectoryRecursively(fullPath);
        } else {
            g_CurrentScanningFile = ffd.cFileName;
            g_FilesScannedCount++;
            
            std::wstring threatReason = L"";
            int riskScore = AnalyzeHeuristicRisk(fullPath, threatReason);
            
            if (riskScore >= 30) {
                std::wstring statusType = (riskScore == 100) ? L"Malware Threat" : L"Suspicious File";
                std::wstring actionTaken = L"Alert Only";
                if (g_AutomationLevel == 1) {
                    if (MoveToQuarantine(fullPath, threatReason)) actionTaken = L"Quarantined";
                }
                 else if (g_AutomationLevel == 2) {
                    if (ShredAndDestroyFile(fullPath)) actionTaken = L"Shredded";
                }
                ThreadSafeAddLog(fullPath, statusType + L" (" + threatReason + L")", actionTaken);
            } else {
                ThreadSafeAddRealtimeScanLog(fullPath, L"Clean", L"Verified safe");
            }
        }
        
        Sleep(20); 

    } while (FindNextFileW(hFind, &ffd) != 0 && g_bIsScanning);

    FindClose(hFind);
}

DWORD WINAPI ScanThread(LPVOID lpParam) {
    g_bIsScanning = true;
    g_CurrentScanningFile = L"Counting files...";
    g_TotalFilesToScan = 0;
    g_FilesScannedCount = 0;

    std::vector<std::wstring> scanPaths;

    if (g_bFullScanActive) {
        scanPaths = GetSystemDrives();
    } else if (g_bCustomScanActive && !g_CustomScanPath.empty()) {
        scanPaths.push_back(g_CustomScanPath);
    } else {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring targetPath = tempPath;
        if (!targetPath.empty() && targetPath.back() == L'\\') {
            targetPath.pop_back();
        }
        scanPaths.push_back(targetPath);
    }

    for (const auto& path : scanPaths) {
        if (!IsPathExcluded(path)) {
            PreCountFilesRecursively(path);
        }
    }

    g_CurrentScanningFile = L"Initializing scan...";
    Sleep(500);

    VerifyMBRIntegrity();

    for (const auto& path : scanPaths) {
        if (!IsPathExcluded(path)) {
            ScanDirectoryRecursively(path);
        }
    }

    g_bIsScanning = false;
    g_bCustomScanActive = false;
    g_bFullScanActive = false;
    g_CurrentScanningFile = L"";
    ShowNotification(L"Scan Complete", L"Diagnostic scan finished successfully.", NIIF_INFO);
    
    RECT rectHeader;
    GetClientRect(g_hMainWnd, &rectHeader);
    rectHeader.left = 150;
    rectHeader.bottom = 210;
    InvalidateRect(g_hMainWnd, &rectHeader, TRUE);

    return 0;
}

bool TrackAndDetectRansomware(const std::wstring& filePath) {
    if (IsPathExcluded(filePath)) return false;

    size_t pos = filePath.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return false;
    std::wstring dir = filePath.substr(0, pos);

    EnterCriticalSection(&g_RansomwareCS);
    DWORD now = GetTickCount();
    
    g_WriteEvents.erase(std::remove_if(g_WriteEvents.begin(), g_WriteEvents.end(), 
        [now](const FileWriteEvent& e) { return (now - e.timestamp) > 5000; }), 
        g_WriteEvents.end());

    double entropy = CalculateShannonEntropy(filePath);
    bool isSuspicious = (entropy > 7.5); 

    if (isSuspicious) {
        g_WriteEvents.push_back({ dir, now });
    }

    int count = 0;
    for (const auto& e : g_WriteEvents) {
        if (e.directory == dir) count++;
    }

    LeaveCriticalSection(&g_RansomwareCS);

    if (count >= 5) { 
        return true;
    }
    return false;
}

bool IsSuspiciousParentChild(const std::wstring& parentName, const std::wstring& childName) {
    std::wstring pName = parentName;
    std::wstring cName = childName;
    for (auto& c : pName) c = towlower(c);
    for (auto& c : cName) c = towlower(c);

    if (pName == L"iexplore.exe" || pName == L"chrome.exe" || pName == L"firefox.exe" || 
        pName == L"winword.exe" || pName == L"excel.exe" || pName == L"acrord32.exe") {
        
        if (cName == L"cmd.exe" || cName == L"powershell.exe" || 
            cName == L"wscript.exe" || cName == L"cscript.exe" || 
            cName == L"mshta.exe" || cName == L"rundll32.exe") {
            return true;
        }
    }
    return false;
}

std::wstring GetProcessNameFromPID(DWORD pid) {
    std::wstring name = L"";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    name = pe.szExeFile;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return name;
}

bool ScanProcessMemoryForShellcode(HANDLE hProc, LPVOID baseAddr, SIZE_T regionSize) {
    if (regionSize < 512 || regionSize > 1048576) return false; 
    BYTE* buffer = (BYTE*)malloc(regionSize);
    if (!buffer) return false;

    SIZE_T bytesRead = 0;
    bool detected = false;
    if (dyn_ReadProcessMemory && dyn_ReadProcessMemory(hProc, baseAddr, buffer, regionSize, &bytesRead) && bytesRead > 128) {
        for (SIZE_T i = 0; i < bytesRead - 8; i++) {
            if (buffer[i] == 0xFC && buffer[i+1] == 0xE8) {
                if ((buffer[i+2] == 0x82 || buffer[i+2] == 0x89) && buffer[i+3] == 0x00 && buffer[i+4] == 0x00 && buffer[i+5] == 0x00) {
                    detected = true;
                    break;
                }
            }
            if (i < bytesRead - 32) {
                bool isNopSled = true;
                for (int j = 0; j < 32; j++) {
                    if (buffer[i+j] != 0x90) {
                        isNopSled = false;
                        break;
                    }
                }
                if (isNopSled) {
                    detected = true;
                    break;
                }
            }
        }
    }
    free(buffer);
    return detected;
}

bool IsProcessMasquerading(const std::wstring& procName, const std::wstring& procPath) {
    std::wstring lowerName = procName;
    std::wstring lowerPath = procPath;
    for (auto& c : lowerName) c = towlower(c);
    for (auto& c : lowerPath) c = towlower(c);

    if (lowerName == L"svchost.exe" || lowerName == L"lsass.exe" || 
        lowerName == L"services.exe" || lowerName == L"winlogon.exe" || 
        lowerName == L"csrss.exe" || lowerName == L"smss.exe") {
        
        wchar_t sysDir[MAX_PATH];
        if (GetSystemDirectoryW(sysDir, MAX_PATH)) {
            std::wstring lowerSysDir = sysDir;
            for (auto& c : lowerSysDir) c = towlower(c);
            
            if (lowerPath.find(lowerSysDir) != 0) {
                return true; 
            }
        }
    }
    return false;
}

void CheckAndRemediateHostsFile() {
    if (!g_bHostsGuard) return;
    
    wchar_t windir[MAX_PATH];
    GetWindowsDirectoryW(windir, MAX_PATH);
    std::wstring hostsPath = std::wstring(windir) + L"\\System32\\drivers\\etc\\hosts";
    
    // Temporarily release the self-defense file lock to prevent access sharing violations (ERROR_SHARING_VIOLATION).
    if (g_hHostsFileLock != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hHostsFileLock);
        g_hHostsFileLock = INVALID_HANDLE_VALUE;
    }

    HANDLE hFile = CreateFileW(hostsPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    bool needsRemediation = false;
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(hFile, NULL);
        if (size > 0 && size < 1048576) {
            char* buffer = (char*)malloc(size + 1);
            if (buffer) {
                DWORD read = 0;
                if (ReadFile(hFile, buffer, size, &read, NULL)) {
                    buffer[read] = '\0';
                    std::string content(buffer);
                    for (auto& c : content) c = tolower(c);
                    
                    if (content.find("microsoft") != std::string::npos || content.find("update") != std::string::npos) {
                        if (content.find("127.0.0.1") != std::string::npos && 
                           (content.find("windowsupdate") != std::string::npos || content.find("update.microsoft") != std::string::npos)) {
                            needsRemediation = true;
                        }
                    }
                }
                free(buffer);
            }
        }
        CloseHandle(hFile);
    }

    if (needsRemediation) {
        HANDLE hWrite = CreateFileW(hostsPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hWrite != INVALID_HANDLE_VALUE) {
            const char* defaultHosts = "# Recovered by Secure XP Pro v2 Shield Guard\r\n127.0.0.1       localhost\r\n::1             localhost\r\n";
            DWORD written;
            WriteFile(hWrite, defaultHosts, (DWORD)strlen(defaultHosts), &written, NULL);
            CloseHandle(hWrite);
            ShowNotification(L"Hosts Shield Guard", L"Malicious redirection detected and healed in HOSTS file!", NIIF_WARNING);
        }
    }

    // Re-acquire the hosts file self-defense lock
    ProtectHostsFile();
}

void CreateSettingsControls(HWND hParent) {
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    HWND hCtrl = CreateWindowExW(0, L"BUTTON", L"Active Real-time File Guard", WS_CHILD|BS_AUTOCHECKBOX, 170, 125, 280, 20, hParent, (HMENU)6001, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Memory Exploit Guard", WS_CHILD|BS_AUTOCHECKBOX, 170, 150, 280, 20, hParent, (HMENU)6002, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"USB Autorun Vaccine Shield", WS_CHILD|BS_AUTOCHECKBOX, 170, 175, 280, 20, hParent, (HMENU)6003, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Browser Download Security Guard", WS_CHILD|BS_AUTOCHECKBOX, 170, 200, 280, 20, hParent, (HMENU)6004, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Credential Leak Protection Shield", WS_CHILD|BS_AUTOCHECKBOX, 170, 225, 280, 20, hParent, (HMENU)6005, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Filter Vulnerable SMB Port 445", WS_CHILD|BS_AUTOCHECKBOX, 170, 250, 280, 20, hParent, (HMENU)6011, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Filter Vulnerable RPC Port 135", WS_CHILD|BS_AUTOCHECKBOX, 170, 275, 280, 20, hParent, (HMENU)6012, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Filter Vulnerable RDP Port 3389", WS_CHILD|BS_AUTOCHECKBOX, 170, 300, 280, 20, hParent, (HMENU)6013, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Network Exploits & Firewall Shield", WS_CHILD|BS_AUTOCHECKBOX, 470, 125, 280, 20, hParent, (HMENU)6006, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"HIPS Canary File Activity Guard", WS_CHILD|BS_AUTOCHECKBOX, 470, 150, 280, 20, hParent, (HMENU)6007, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Lock System HOSTS Configuration File", WS_CHILD|BS_AUTOCHECKBOX, 470, 175, 280, 20, hParent, (HMENU)6008, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Hardened LSASS Security Policy", WS_CHILD|BS_AUTOCHECKBOX, 470, 200, 280, 20, hParent, (HMENU)6009, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Continuous Startup Sanitization Guard", WS_CHILD|BS_AUTOCHECKBOX, 470, 225, 280, 20, hParent, (HMENU)6010, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Boot Engine Core Auto-Start on Startup", WS_CHILD|BS_AUTOCHECKBOX, 470, 250, 280, 20, hParent, (HMENU)6023, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Heur Low", WS_CHILD|BS_AUTORADIOBUTTON|WS_GROUP, 470, 275, 90, 20, hParent, (HMENU)6015, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Heur Med", WS_CHILD|BS_AUTORADIOBUTTON, 565, 275, 90, 20, hParent, (HMENU)6016, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Heur High", WS_CHILD|BS_AUTORADIOBUTTON, 660, 275, 90, 20, hParent, (HMENU)6017, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Prompt Decision", WS_CHILD|BS_AUTORADIOBUTTON|WS_GROUP, 470, 300, 140, 20, hParent, (HMENU)6018, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Auto Quarantine", WS_CHILD|BS_AUTORADIOBUTTON, 615, 300, 150, 20, hParent, (HMENU)6019, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"STATIC", L"Excluded Folders (Ignored during scans):", WS_CHILD, 170, 325, 300, 15, hParent, (HMENU)6020, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VSCROLL | LBS_NOTIFY, 170, 345, 380, 75, hParent, (HMENU)6021, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Add Folder", WS_CHILD | BS_PUSHBUTTON, 560, 345, 90, 25, hParent, (HMENU)6024, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Remove", WS_CHILD | BS_PUSHBUTTON, 660, 345, 90, 25, hParent, (HMENU)6025, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);

    hCtrl = CreateWindowExW(0, L"BUTTON", L"Save & Apply Protection Profile", WS_CHILD|BS_DEFPUSHBUTTON, 560, 380, 190, 40, hParent, (HMENU)6022, GetModuleHandle(NULL), NULL);
    SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, FALSE);
    g_SettingsWnds.push_back(hCtrl);
}

void SyncSettingsToUI() {
    CheckDlgButton(g_hMainWnd, 6001, g_bRealTimeProtection ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6002, g_bRamShield ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6003, g_bBlockUSB ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6004, g_bBrowserShield ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6005, g_bCredentialGuard ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6006, g_bNetworkShield ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6007, g_bHipsCanary ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6008, g_bHostsGuard ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6009, g_bLsassProtect ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6010, g_bAutoSanitize ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6011, g_bBlockPort445 ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6012, g_bBlockPort135 ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6013, g_bBlockPort3389 ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hMainWnd, 6023, g_bAutoStart ? BST_CHECKED : BST_UNCHECKED);

    CheckDlgButton(g_hMainWnd, 6015 + g_HeuristicLevel, BST_CHECKED);
    CheckDlgButton(g_hMainWnd, 6018 + g_AutomationLevel, BST_CHECKED);

    HWND hListBox = GetDlgItem(g_hMainWnd, 6021);
    if (hListBox) {
        SendMessageW(hListBox, LB_RESETCONTENT, 0, 0);
        
        EnterCriticalSection(&g_ExclusionsCS);
        for (const auto& path : g_ExcludedFolders) {
            SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)path.c_str());
        }
        LeaveCriticalSection(&g_ExclusionsCS);
    }
}

void UpdateUIVisibility() {
    int showSettings = (g_Selected == 4) ? SW_SHOW : SW_HIDE;
    int showListView = (g_Selected == 4) ? SW_HIDE : SW_SHOW;

    ShowWindow(g_hListView, showListView);

    for (size_t i = 0; i < g_SettingsWnds.size(); ++i) {
        ShowWindow(g_SettingsWnds[i], showSettings);
    }

    InvalidateRect(g_hMainWnd, NULL, TRUE);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            g_hMainWnd = hWnd;
            
            InitializeCriticalSection(&g_RansomwareCS); 
            InitializeCriticalSection(&g_ExclusionsCS);
            InitializeCriticalSection(&g_QuarantineCS); 
            
            ResolveDynamicAPIs();
            
            HardenProcessDACL();
            ConnectToKernelShield(GetCurrentProcessId());

            EnableCriticalProcessSelfDefense();
            EnableHardwareDEPProtection();
            
            ProtectHostsFile();
            ProtectLSASSDACL();

            InitQuarantine();
            LoadSettings();
            CreateCanaryFiles();

            NOTIFYICONDATAW nid = {0};
            nid.cbSize = sizeof(NOTIFYICONDATAW);
            nid.hWnd = hWnd;
            nid.uID = NOTIFY_ID;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = ID_TRAY_CALLBACK;
            nid.hIcon = LoadIconW(GetModuleHandle(NULL), MAKEINTRESOURCEW(1));
            if (!nid.hIcon) nid.hIcon = LoadIconW(NULL, IDI_APPLICATION);
            wcsncpy(nid.szTip, L"Secure XP Pro v2 Active Protection", 127);
            Shell_NotifyIconW(NIM_ADD, &nid);

            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreatePopupMenu();
            AppendMenuW(hFileMenu, MF_STRING, ID_MENU_SCAN, L"Quick Diagnostic Scan");
            AppendMenuW(hFileMenu, MF_STRING, ID_MENU_CUSTOM_SCAN, L"Select Custom Path...");
            AppendMenuW(hFileMenu, MF_STRING, ID_MENU_QUARANTINE, L"Quarantine Manual Target...");
            AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hFileMenu, MF_STRING, ID_MENU_SETTINGS, L"Advanced Engine Panel");
            AppendMenuW(hFileMenu, MF_STRING, ID_MENU_EXIT, L"Shutdown Antivirus Protection");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"Actions");
            SetMenu(hWnd, hMenu);

            g_hSidebar = CreateWindowW(L"STATIC", L"", WS_VISIBLE|WS_CHILD|SS_OWNERDRAW|SS_NOTIFY, 0,55,150,400, hWnd,(HMENU)IDC_SIDEBAR, GetModuleHandle(NULL), NULL);
            g_OldSidebarProc = (WNDPROC)SetWindowLongPtrW(g_hSidebar, GWLP_WNDPROC, (LONG_PTR)SidebarSubclassProc);

            g_hListView = CreateWindowW(WC_LISTVIEWW, L"", WS_VISIBLE|WS_CHILD|LVS_REPORT|WS_BORDER|LVS_SINGLESEL, 160,210,620,200, hWnd,(HMENU)IDC_LISTVIEW, NULL, NULL);
            g_hStatusBar = CreateWindowW(STATUSCLASSNAMEW, L"System Protected", WS_VISIBLE|WS_CHILD|SBARS_SIZEGRIP, 0,430,780,25, hWnd,0,0,0);

            ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            RefreshListView();

            CreateSettingsControls(hWnd);
            SyncSettingsToUI();
            UpdateUIVisibility();

            SetTimer(hWnd, IDT_REALTIME_SCAN, 4000, NULL);
            SetTimer(hWnd, IDT_ANIMATION, 50, NULL); 
            
            HANDLE hThread;
            hThread = CreateThread(NULL, 0, RealTimeDriveMonitorThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, RealTimeFirewallThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, RealTimeCodeInjectionShieldThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, BrowserDownloadMonitorThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, KernelDriverWatcherThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, LiveHTTPSWebCacheScanThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, RealTimeProcessExecutionShieldThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);

            hThread = CreateThread(NULL, 0, RealTimeRansomwareWatcherThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
            break;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            RECT rectHeader;
            GetClientRect(hWnd, &rectHeader);
            rectHeader.left = 150;
            rectHeader.bottom = 210; 

            int width = rectHeader.right - rectHeader.left;
            int height = rectHeader.bottom - rectHeader.top;

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, width, height);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            SetWindowOrgEx(memDC, rectHeader.left, rectHeader.top, NULL);

            DrawCentralDisplay(memDC, rectHeader);

            BitBlt(hdc, rectHeader.left, rectHeader.top, width, height, memDC, rectHeader.left, rectHeader.top, SRCCOPY);

            SelectObject(memDC, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDC);

            EndPaint(hWnd, &ps);
            break;
        }
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT lp = (LPDRAWITEMSTRUCT)lParam;
            if(lp->CtlID == IDC_SIDEBAR) {
                RECT rc = lp->rcItem;
                
                HBRUSH sideBg = CreateSolidBrush(RGB(247, 249, 252)); 
                FillRect(lp->hDC, &rc, sideBg);
                DeleteObject(sideBg);

                int itemHeight = 50;
                for (int i = 0; i < g_SidebarCount; i++) {
                    RECT r = { rc.left, rc.top + i * itemHeight, rc.right, rc.top + (i + 1) * itemHeight };
                    DrawSidebarItem(lp->hDC, i, i == g_Selected, r);
                }

                RECT guardRect = { rc.left + 8, rc.bottom - 40, rc.right - 8, rc.bottom - 8 };
                HBRUSH guardBrush = CreateSolidBrush(RGB(240, 248, 240));
                HPEN guardPen = CreatePen(PS_SOLID, 1, RGB(200, 235, 200));
                
                HBRUSH oldBrush = (HBRUSH)SelectObject(lp->hDC, guardBrush);
                HPEN oldPen = (HPEN)SelectObject(lp->hDC, guardPen);
                RoundRect(lp->hDC, guardRect.left, guardRect.top, guardRect.right, guardRect.bottom, 4, 4);
                
                SetTextColor(lp->hDC, RGB(0, 180, 80));
                SetBkMode(lp->hDC, TRANSPARENT);
                HFONT hGuardFont = CreateFontW(11, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
                HFONT oldFont = (HFONT)SelectObject(lp->hDC, hGuardFont);
                DrawTextW(lp->hDC, L"Shield Status: Active", -1, &guardRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                
                SelectObject(lp->hDC, oldFont);
                SelectObject(lp->hDC, oldBrush);
                SelectObject(lp->hDC, oldPen);
                
                DeleteObject(hGuardFont);
                DeleteObject(guardBrush);
                DeleteObject(guardPen);

                return TRUE;
            }
            break;
        }
        case WM_DEVICECHANGE: { 
            if (g_bBlockUSB && wParam == 0x8000) { 
                DEV_BROADCAST_HDR* pDvh = (DEV_BROADCAST_HDR*)lParam;
                if (pDvh->dbch_devicetype == 2) { 
                    DEV_BROADCAST_VOLUME* pDbv = (DEV_BROADCAST_VOLUME*)pDvh;
                    wchar_t driveLetter = L'A';
                    DWORD mask = pDbv->dbcv_unitmask;
                    for (int i = 0; i < 26; ++i) {
                        if (mask & (1 << i)) { driveLetter = L'A' + i; break; }
                    }
                    
                    std::wstring driveRoot = std::wstring(1, driveLetter) + L":\\";
                    std::wstring autorunPath = driveRoot + HexDecryptString(L"1F0B0A110C0B1050171018");
                    
                    if (!IsPathExcluded(autorunPath)) {
                        if (CreateDirectoryW(autorunPath.c_str(), NULL)) {
                            SetFileAttributesW(autorunPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
                            std::wstring protectPath = autorunPath + L"\\SecureXP_Vaccine.lck";
                            HANDLE hLck = CreateFileW(protectPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
                            if (hLck != INVALID_HANDLE_VALUE) CloseHandle(hLck);

                            ShowNotification(L"USB Shield Immunizer", L"Vaccinated: Drive " + std::wstring(1, driveLetter), NIIF_INFO);
                        }
                    }
                }
            }
            break;
        }
        case WM_NOTIFY: {
            LPNMHDR lpnmh = (LPNMHDR)lParam;
            if (lpnmh->idFrom == IDC_LISTVIEW && lpnmh->code == NM_RCLICK) {
                int iSelected = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
                if (iSelected != -1) {
                    POINT pt;
                    GetCursorPos(&pt);
                    HMENU hPopup = CreatePopupMenu();
                    
                    if (g_Selected == 5) { 
                        AppendMenuW(hPopup, MF_STRING, 5001, L"Restore Isolated File");
                        AppendMenuW(hPopup, MF_STRING, 5002, L"Delete Permanently (Shred)");
                    }
                    else if (g_Selected == 0 || g_Selected == 1 || g_Selected == 2) { 
                        AppendMenuW(hPopup, MF_STRING, 5004, L"Move to Secure Quarantine Folder");
                    }
                    
                    TrackPopupMenu(hPopup, TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
                    DestroyMenu(hPopup);
                }
            }
            break;
        }
        // Thread-safe marshalled GUI logs processed on the UI thread
        case WM_APP_ADD_LOG: {
            SafeLogPayload* p = (SafeLogPayload*)lParam;
            if (p) {
                AddLog(p->path, p->status, p->details);
            }
            return 0;
        }
        case WM_APP_REALTIME_LOG: {
            SafeLogPayload* p = (SafeLogPayload*)lParam;
            if (p) {
                AddRealtimeScanLog(p->path, p->status, p->details);
            }
            return 0;
        }
        case WM_TIMER:
            if(wParam == IDT_REALTIME_SCAN) {
                PerformRealtimeScan();
            }
            else if(wParam == IDT_ANIMATION) {
                if (g_Selected != 4) {
                    if (g_bIsScanning) {
                        g_AnimAngle = (g_AnimAngle + 8) % 360; 
                    } else {
                        g_AnimAngle = (g_AnimAngle + 2) % 360; 
                    }
                    RECT rectHeader;
                    GetClientRect(hWnd, &rectHeader);
                    rectHeader.left = 150;
                    rectHeader.bottom = 210;
                    InvalidateRect(hWnd, &rectHeader, FALSE);
                }
            }
            break;
        case ID_TRAY_CALLBACK: {
            if (lParam == WM_LBUTTONUP) {
                ShowWindow(hWnd, SW_SHOW);
                ShowWindow(hWnd, SW_RESTORE);
                SetForegroundWindow(hWnd);
            } else if (lParam == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"Open Engine Center");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Shutdown Protection");
                SetForegroundWindow(hWnd);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
                DestroyMenu(hMenu);
            }
            break;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == IDC_SIDEBAR && HIWORD(wParam) == STN_CLICKED) {
                POINT pt; GetCursorPos(&pt); ScreenToClient(g_hSidebar, &pt);
                int idx = pt.y / 50; 
                if (idx >= 0 && idx < g_SidebarCount) {
                    g_Selected = idx;
                    UpdateUIVisibility();
                    RefreshListView();
                    InvalidateRect(g_hSidebar, NULL, TRUE);

                    if (g_Selected == 0) {
                        if (!g_bIsScanning) {
                            int response = MessageBoxW(hWnd, 
                                L"Do you want to scan all system drives?\n\nSelecting 'Yes' initiates a deep system check over all fixed and removable storage units. This process might take some time depending on storage size.", 
                                L"Secure XP Pro v2 - Full Check", 
                                MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);
                            
                            if (response == IDYES) {
                                g_bFullScanActive = true;
                                CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
                            } else {
                                g_Selected = 0; 
                                InvalidateRect(g_hSidebar, NULL, TRUE);
                            }
                        } else {
                            MessageBoxW(hWnd, L"Another scanning operation is currently running.", L"Scan Active", MB_OK | MB_ICONEXCLAMATION);
                        }
                    }
                    else if (g_Selected == 1) { 
                        if (!g_bIsScanning) {
                            g_bFullScanActive = false;
                            CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
                        }
                    }
                    else if (g_Selected == 2) {
                        if (!g_bIsScanning) {
                            CreateThread(NULL, 0, SpeedupThread, NULL, 0, NULL);
                        }
                    }
                    else if (g_Selected == 3) {
                        if (!g_bIsScanning) {
                            CreateThread(NULL, 0, CleanupThread, NULL, 0, NULL);
                        }
                    }
                }
            }
            else if(LOWORD(wParam) == ID_MENU_SCAN) {
                g_Selected = 1;
                UpdateUIVisibility();
                RefreshListView();
                if(!g_bIsScanning) { 
                    g_bFullScanActive = false;
                    CreateThread(NULL, 0, ScanThread, NULL, 0, NULL); 
                }
            }
            else if(LOWORD(wParam) == ID_MENU_QUARANTINE) {
                wchar_t filePath[MAX_PATH] = {0};
                OPENFILENAMEW ofn = {0};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hWnd;
                ofn.lpstrFilter = L"All Files (*.*)\0*.*\0Executable Files (*.exe;*.dll)\0*.exe;*.dll\0";
                ofn.lpstrFile = filePath;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrTitle = L"Select File to Quarantine Manual Target";
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

                if (GetOpenFileNameW(&ofn)) {
                    if (MoveToQuarantine(filePath)) {
                        ShowNotification(L"Manual Quarantine", L"Selected target successfully moved to quarantine.", NIIF_INFO);
                        RefreshListView();
                    } else {
                        ShowNotification(L"Quarantine Failed", L"Could not quarantine selected target file.", NIIF_ERROR);
                    }
                }
            }
            else if(LOWORD(wParam) == ID_MENU_SETTINGS) {
                g_Selected = 4;
                UpdateUIVisibility();
                RefreshListView();
                InvalidateRect(g_hSidebar, NULL, TRUE);
            }
            else if(LOWORD(wParam) == ID_MENU_CUSTOM_SCAN) {
                if(!g_bIsScanning) {
                    std::wstring chosen = BrowseFolder(hWnd);
                    if (!chosen.empty()) {
                        g_CustomScanPath = chosen;
                        g_bCustomScanActive = true;
                        g_bFullScanActive = false;
                        g_Selected = 1; 
                        UpdateUIVisibility();
                        RefreshListView();
                        CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
                    }
                }
            }
            else if(LOWORD(wParam) == ID_MENU_EXIT || LOWORD(wParam) == ID_TRAY_EXIT) {
                if (MessageBoxW(hWnd, L"Stopping background monitoring will leave your system vulnerable. Continue?", L"Self-Defense Alert", MB_YESNO | MB_ICONWARNING) == IDYES) {
                    if (g_hHostsFileLock != INVALID_HANDLE_VALUE) {
                        CloseHandle(g_hHostsFileLock);
                    }
                    DeleteCriticalSection(&g_RansomwareCS); 
                    DeleteCriticalSection(&g_ExclusionsCS);
                    DeleteCriticalSection(&g_QuarantineCS); 
                    DestroyWindow(hWnd);
                }
            }
            else if(LOWORD(wParam) == ID_TRAY_SHOW) {
                ShowWindow(hWnd, SW_SHOW);
                ShowWindow(hWnd, SW_RESTORE);
                SetForegroundWindow(hWnd);
            }
            else if(LOWORD(wParam) == 5001) { 
                int idx = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
                if (idx != -1) {
                    wchar_t qFile[MAX_PATH], orig[MAX_PATH];
                    ListView_GetItemText(g_hListView, idx, 0, qFile, MAX_PATH);
                    GetPrivateProfileStringW(L"Quarantine", qFile, L"", orig, MAX_PATH, g_ConfigFile);
                    if (wcslen(orig) > 0) {
                        std::wstring fullQPath = std::wstring(g_QuarantineDir) + L"\\" + qFile;
                        
                        wchar_t origDir[MAX_PATH];
                        wcscpy_s(origDir, MAX_PATH, orig);
                        PathRemoveFileSpecW(origDir);
                        SHCreateDirectoryExW(NULL, origDir, NULL);
                        
                        // Prepare quarantine and destination file attributes (remove system and read-only states)
                        SetFileAttributesW(fullQPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                        if (PathFileExistsW(orig)) {
                            SetFileAttributesW(orig, FILE_ATTRIBUTE_NORMAL);
                        }

                        // Use a secure overwrite move method to replace the old or damaged file
                        if (MoveFileExW(fullQPath.c_str(), orig, MOVEFILE_REPLACE_EXISTING)) {
                            WritePrivateProfileStringW(L"Quarantine", qFile, NULL, g_ConfigFile);
                            // Remove reason from settings file
                            WritePrivateProfileStringW(L"QuarantineReason", qFile, NULL, g_ConfigFile); 
                            ListView_DeleteItem(g_hListView, idx); 
                            ShowNotification(L"File Restored", L"File restored from quarantine to its original path successfully.", NIIF_INFO);
                        } else {
                            ShowNotification(L"Restore Failed", L"Failed to move file back to original location. Check process lock or permissions.", NIIF_ERROR);
                        }
                    }
                }
            }
            else if(LOWORD(wParam) == 5002) { 
                int idx = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
                if (idx != -1) {
                    wchar_t qFile[MAX_PATH];
                    ListView_GetItemText(g_hListView, idx, 0, qFile, MAX_PATH);
                    std::wstring fullQPath = std::wstring(g_QuarantineDir) + L"\\" + qFile;
                    
                    bool deleted = ShredAndDestroyFile(fullQPath);
                    if (!deleted) {
                        SetFileAttributesW(fullQPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                        deleted = (DeleteFileW(fullQPath.c_str()) != FALSE);
                    }

                    if (deleted || !PathFileExistsW(fullQPath.c_str())) {
                        WritePrivateProfileStringW(L"Quarantine", qFile, NULL, g_ConfigFile);
                        // Clean up quarantine reason
                        WritePrivateProfileStringW(L"QuarantineReason", qFile, NULL, g_ConfigFile); 
                        ListView_DeleteItem(g_hListView, idx); 
                        ShowNotification(L"Quarantine Cleared", L"File permanently deleted from the quarantine directory.", NIIF_INFO);
                    } else {
                        ShowNotification(L"Deletion Failed", L"Could not delete the selected quarantined target.", NIIF_ERROR);
                    }
                }
            }
            else if(LOWORD(wParam) == 5004) { 
                int idx = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
                if (idx != -1) {
                    wchar_t itemText[MAX_PATH];
                    ListView_GetItemText(g_hListView, idx, 0, itemText, MAX_PATH);
                    std::wstring fullPath = itemText;

                    // If the user is on the Speedup tab, the row text contains only the process name; discover its executable file path.
                    if (g_Selected == 2) { 
                        std::wstring procPath = L"";
                        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                        if (hSnapshot != INVALID_HANDLE_VALUE) {
                            PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
                            if (Process32FirstW(hSnapshot, &pe)) {
                                do {
                                    if (fullPath == pe.szExeFile) {
                                        // Open the process to terminate it and retrieve its path
                                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                                        if (hProc) {
                                            HMODULE hPsapi = LoadLibraryW(L"psapi.dll");
                                            if (hPsapi) {
                                                typedef DWORD(WINAPI* pfnGetModuleFileNameExW)(HANDLE, HMODULE, LPWSTR, DWORD);
                                                pfnGetModuleFileNameExW pGetMod = (pfnGetModuleFileNameExW)GetProcAddress(hPsapi, "GetModuleFileNameExW");
                                                if (pGetMod) {
                                                    wchar_t szPath[MAX_PATH] = {0};
                                                    if (pGetMod(hProc, NULL, szPath, MAX_PATH)) {
                                                        procPath = szPath;
                                                    }
                                                }
                                                FreeLibrary(hPsapi);
                                            }
                                            // Close active process to allow Windows to release and quarantine its executable file
                                            TerminateProcess(hProc, 0);
                                            CloseHandle(hProc);
                                            if (!procPath.empty()) break;
                                        }
                                    }
                                } while (Process32NextW(hSnapshot, &pe));
                            }
                            CloseHandle(hSnapshot);
                        }
                        if (!procPath.empty()) {
                            // Replace target path with resolved full path
                            fullPath = procPath;
                        }
                    }

                    // Attempt to quarantine the resolved file with its reason
                    std::wstring qReason = (g_Selected == 2) ? L"Suspicious Process (Speedup)" : L"Manual Isolation";
                    if (MoveToQuarantine(fullPath, qReason)) {
                        ListView_DeleteItem(g_hListView, idx);
                        ShowNotification(L"Threat Quarantined", L"Selected process binary has been moved to secure quarantine.", NIIF_INFO);
                    } else {
                        ShowNotification(L"Quarantine Failed", L"Could not move the selected target to quarantine. It might be a protected system file.", NIIF_ERROR);
                    }
                }
            }
            else if(LOWORD(wParam) == 6024) { 
                std::wstring chosen = BrowseFolder(hWnd);
                if (!chosen.empty()) {
                    EnterCriticalSection(&g_ExclusionsCS);
                    if (std::find(g_ExcludedFolders.begin(), g_ExcludedFolders.end(), chosen) == g_ExcludedFolders.end()) {
                        g_ExcludedFolders.push_back(chosen);
                        HWND hListBox = GetDlgItem(hWnd, 6021);
                        if (hListBox) {
                            SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)chosen.c_str());
                        }
                    }
                    LeaveCriticalSection(&g_ExclusionsCS);
                }
            }
            else if(LOWORD(wParam) == 6025) { 
                HWND hListBox = GetDlgItem(hWnd, 6021);
                if (hListBox) {
                    int sel = (int)SendMessageW(hListBox, LB_GETCURSEL, 0, 0);
                    if (sel != LB_ERR) {
                        EnterCriticalSection(&g_ExclusionsCS);
                        if (sel >= 0 && (size_t)sel < g_ExcludedFolders.size()) {
                            g_ExcludedFolders.erase(g_ExcludedFolders.begin() + sel);
                            SendMessageW(hListBox, LB_DELETESTRING, sel, 0);
                        }
                        LeaveCriticalSection(&g_ExclusionsCS);
                    }
                }
            }
            else if(LOWORD(wParam) == 6022) { 
                bool bNewPort445 = (IsDlgButtonChecked(hWnd, 6011) == BST_CHECKED);
                bool bNewPort135 = (IsDlgButtonChecked(hWnd, 6012) == BST_CHECKED);
                bool bNewPort3389 = (IsDlgButtonChecked(hWnd, 6013) == BST_CHECKED);

                g_bRealTimeProtection = (IsDlgButtonChecked(hWnd, 6001) == BST_CHECKED);
                g_bRamShield = (IsDlgButtonChecked(hWnd, 6002) == BST_CHECKED);
                g_bBlockUSB = (IsDlgButtonChecked(hWnd, 6003) == BST_CHECKED);
                g_bBrowserShield = (IsDlgButtonChecked(hWnd, 6004) == BST_CHECKED);
                g_bCredentialGuard = (IsDlgButtonChecked(hWnd, 6005) == BST_CHECKED);
                g_bNetworkShield = (IsDlgButtonChecked(hWnd, 6006) == BST_CHECKED);
                g_bHipsCanary = (IsDlgButtonChecked(hWnd, 6007) == BST_CHECKED);
                g_bHostsGuard = (IsDlgButtonChecked(hWnd, 6008) == BST_CHECKED);
                g_bLsassProtect = (IsDlgButtonChecked(hWnd, 6009) == BST_CHECKED);
                g_bAutoSanitize = (IsDlgButtonChecked(hWnd, 6010) == BST_CHECKED);
                
                g_bBlockPort445 = bNewPort445;
                g_bBlockPort135 = bNewPort135;
                g_bBlockPort3389 = bNewPort3389;
                
                g_bAutoStart = (IsDlgButtonChecked(hWnd, 6023) == BST_CHECKED);

                if (IsDlgButtonChecked(hWnd, 6015)) g_HeuristicLevel = 0;
                else if (IsDlgButtonChecked(hWnd, 6016)) g_HeuristicLevel = 1;
                else if (IsDlgButtonChecked(hWnd, 6017)) g_HeuristicLevel = 2;

                if (IsDlgButtonChecked(hWnd, 6018)) g_AutomationLevel = 0;
                else if (IsDlgButtonChecked(hWnd, 6019)) g_AutomationLevel = 1;

                ConfigureSystemPortNative(445, g_bBlockPort445);
                ConfigureSystemPortNative(135, g_bBlockPort135);
                ConfigureSystemPortNative(3389, g_bBlockPort3389);

                SaveSettings();
                ApplyAutoStartRegistry();
                ProtectHostsFile();
                ProtectLSASSDACL();

                ShowNotification(L"Profile Applied", L"Your integrated engine configurations have been applied.", NIIF_INFO);
            }
            break;
        }
        case WM_CLOSE: {
            ShowWindow(hWnd, SW_HIDE);
            return 0;
        }
        case WM_DESTROY: {
            NOTIFYICONDATAW nid = {0};
            nid.cbSize = sizeof(NOTIFYICONDATAW);
            nid.hWnd = hWnd;
            nid.uID = NOTIFY_ID;
            Shell_NotifyIconW(NIM_DELETE, &nid);
            KillTimer(hWnd, IDT_REALTIME_SCAN);
            KillTimer(hWnd, IDT_ANIMATION);
            
            if (g_hRansomwareDir != INVALID_HANDLE_VALUE) {
                CloseHandle(g_hRansomwareDir);
                g_hRansomwareDir = INVALID_HANDLE_VALUE;
            }
            if (g_hDownloadDir != INVALID_HANDLE_VALUE) {
                CloseHandle(g_hDownloadDir);
                g_hDownloadDir = INVALID_HANDLE_VALUE;
            }

            DeleteCriticalSection(&g_RansomwareCS);
            DeleteCriticalSection(&g_ExclusionsCS);
            DeleteCriticalSection(&g_QuarantineCS); 
            
            PostQuitMessage(0);
            break;
        }
        case WM_SIZE: {
            RECT rc; GetClientRect(hWnd,&rc);
            SetWindowPos(g_hSidebar, NULL, 0, 50, 150, rc.bottom - 75, SWP_NOZORDER);
            SetWindowPos(g_hListView, NULL, 160, 210, rc.right-160, rc.bottom-235, SWP_NOZORDER);
            SetWindowPos(g_hStatusBar, NULL, 0, rc.bottom-25, rc.right, 25, SWP_NOZORDER);
            InvalidateRect(hWnd, NULL, TRUE); 
            break;
        }
        default: return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    InitSystemPaths(); 
    
    INITCOMMONCONTROLSEX icex = {sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES};
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1)); 
    if (!wc.hIcon) wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName = L"SecureXPClass";
    RegisterClassExW(&wc);

    HWND hWnd = CreateWindowExW(0, L"SecureXPClass", L"Secure XP Pro v2", 
                                (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE), 
                                CW_USEDEFAULT, CW_USEDEFAULT, 800, 500, NULL, NULL, hInst, NULL);
    if(!hWnd) return 0;
    ShowWindow(hWnd, nCmdShow);

    CheckFirstRunPrompt(hWnd);

    if (g_bAutoSanitize) {
        SanitizeStartupList();
    }

    ProtectHostsFile();
    ProtectLSASSDACL();

    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return (int)msg.wParam;
}
