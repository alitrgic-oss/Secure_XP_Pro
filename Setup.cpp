#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

enum WizardStep {
    STEP_WELCOME = 0,
    STEP_EULA,
    STEP_DIRECTORY,
    STEP_OPTIONS,
    STEP_READY,
    STEP_INSTALLING,
    STEP_FINISH
};

struct InstallParams {
    HWND hwnd;
    wchar_t installPath[MAX_PATH];
    BOOL desktopShortcut;
    BOOL startMenuShortcut;
};

WizardStep g_CurrentStep = STEP_WELCOME;

HWND g_hMainWnd = NULL;
HWND g_hNextBtn = NULL;
HWND g_hBackBtn = NULL;
HWND g_hCancelBtn = NULL;

wchar_t g_InstallPath[MAX_PATH] = L"C:\\Program Files\\SecureXP Antivirus";
BOOL g_CreateDesktopShortcut = TRUE;
BOOL g_CreateStartMenuShortcut = TRUE;

HWND g_hEulaEdit = NULL;
HWND g_hEulaRadioAgree = NULL;
HWND g_hEulaRadioDisAgree = NULL;
HWND g_hEditPath = NULL;
HWND g_hBrowseBtn = NULL;
HWND g_hCheckDesktop = NULL;
HWND g_hCheckStartMenu = NULL;
HWND g_hProgressBar = NULL;
HWND g_hStatusText = NULL;

std::string LoadResourceText(int resId) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResInfo = FindResourceW(hModule, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hResInfo) return "";
    HGLOBAL hResData = LoadResource(hModule, hResInfo);
    if (!hResData) return "";
    DWORD dwSize = SizeofResource(hModule, hResInfo);
    LPVOID pData = LockResource(hResData);
    if (!pData) return "";
    return std::string((char*)pData, dwSize);
}

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstr[0], size);
    return wstr;
}

bool ExtractAntivirus(const std::wstring& destFile) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResInfo = FindResourceW(hModule, MAKEINTRESOURCEW(100), RT_RCDATA);
    if (!hResInfo) return false;
    HGLOBAL hResData = LoadResource(hModule, hResInfo);
    if (!hResData) return false;
    DWORD dwSize = SizeofResource(hModule, hResInfo);
    LPVOID pData = LockResource(hResData);
    if (!pData) return false;
    
    HANDLE hFile = CreateFileW(destFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD dwWritten;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return true;
}

bool CreateShortcuts(const std::wstring& targetExe) {
    CoInitialize(NULL);
    
    if (g_CreateDesktopShortcut) {
        wchar_t desktopPath[MAX_PATH];
        if (SHGetSpecialFolderPathW(NULL, desktopPath, CSIDL_DESKTOP, FALSE)) {
            std::wstring shortcutPath = std::wstring(desktopPath) + L"\\SecureXP Antivirus.lnk";
            IShellLinkW* psl;
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl))) {
                IPersistFile* ppf;
                psl->SetPath(targetExe.c_str());
                psl->SetWorkingDirectory(g_InstallPath);
                psl->SetDescription(L"SecureXP Active Heuristic Antivirus");
                psl->SetIconLocation(targetExe.c_str(), 0);
                if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf))) {
                    ppf->Save(shortcutPath.c_str(), TRUE);
                    ppf->Release();
                }
                psl->Release();
            }
        }
    }

    if (g_CreateStartMenuShortcut) {
        wchar_t startMenuPath[MAX_PATH];
        if (SHGetSpecialFolderPathW(NULL, startMenuPath, CSIDL_PROGRAMS, FALSE)) {
            std::wstring dirPath = std::wstring(startMenuPath) + L"\\SecureXP";
            CreateDirectoryW(dirPath.c_str(), NULL);
            std::wstring shortcutPath = dirPath + L"\\SecureXP Antivirus.lnk";
            IShellLinkW* psl;
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl))) {
                IPersistFile* ppf;
                psl->SetPath(targetExe.c_str());
                psl->SetWorkingDirectory(g_InstallPath);
                psl->SetDescription(L"SecureXP Active Heuristic Antivirus");
                psl->SetIconLocation(targetExe.c_str(), 0);
                if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf))) {
                    ppf->Save(shortcutPath.c_str(), TRUE);
                    ppf->Release();
                }
                psl->Release();
            }
        }
    }
    CoUninitialize();
    return true;
}

std::wstring BrowseInstallFolder(HWND hwnd) {
    wchar_t path[MAX_PATH] = {0};
    BROWSEINFOW bi = {0};
    bi.hwndOwner = hwnd;
    bi.lpszTitle = L"Select Destination Folder:";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | 0x0040;
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

DWORD WINAPI InstallThread(LPVOID lpParam) {
    InstallParams* params = (InstallParams*)lpParam;
    HWND hwnd = params->hwnd;

    SendMessage(g_hProgressBar, PBM_SETPOS, 10, 0);
    SetWindowTextW(g_hStatusText, L"Verifying system requirement dependencies...");
    Sleep(600);

    SendMessage(g_hProgressBar, PBM_SETPOS, 25, 0);
    SetWindowTextW(g_hStatusText, L"Allocating file paths and directories...");
    SHCreateDirectoryExW(hwnd, params->installPath, NULL);
    Sleep(500);

    SendMessage(g_hProgressBar, PBM_SETPOS, 50, 0);
    SetWindowTextW(g_hStatusText, L"Extracting SecureXP.exe to target path...");
    std::wstring destFile = std::wstring(params->installPath) + L"\\SecureXP.exe";
    ExtractAntivirus(destFile);
    Sleep(800);

    SendMessage(g_hProgressBar, PBM_SETPOS, 75, 0);
    SetWindowTextW(g_hStatusText, L"Creating system links and environment shortcuts...");
    CreateShortcuts(destFile);
    Sleep(600);

    SendMessage(g_hProgressBar, PBM_SETPOS, 95, 0);
    SetWindowTextW(g_hStatusText, L"Finalizing security configuration profile parameters...");
    Sleep(500);

    SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
    Sleep(200);

    PostMessage(hwnd, WM_USER + 101, 0, 0);

    delete params;
    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            g_hBackBtn = CreateWindowExW(0, L"BUTTON", L"< &Back", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON|WS_DISABLED, 230, 325, 75, 25, hWnd, (HMENU)101, NULL, NULL);
            g_hNextBtn = CreateWindowExW(0, L"BUTTON", L"&Next >", WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON, 310, 325, 75, 25, hWnd, (HMENU)102, NULL, NULL);
            g_hCancelBtn = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 395, 325, 75, 25, hWnd, (HMENU)103, NULL, NULL);
            
            SendMessage(g_hBackBtn, WM_SETFONT, (WPARAM)hFont, FALSE);
            SendMessage(g_hNextBtn, WM_SETFONT, (WPARAM)hFont, FALSE);
            SendMessage(g_hCancelBtn, WM_SETFONT, (WPARAM)hFont, FALSE);

            PostMessage(hWnd, WM_USER + 100, 0, STEP_WELCOME);
            break;
        }
        case WM_USER + 100: { 
            int step = (int)lParam;
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            
            HWND hCur = GetWindow(hWnd, GW_CHILD);
            while(hCur) {
                HWND hNxt = GetWindow(hCur, GW_HWNDNEXT);
                if (hCur != g_hBackBtn && hCur != g_hNextBtn && hCur != g_hCancelBtn) {
                    DestroyWindow(hCur);
                }
                hCur = hNxt;
            }

            if (step == STEP_WELCOME) {
                EnableWindow(g_hBackBtn, FALSE);
                EnableWindow(g_hNextBtn, TRUE);
                SetWindowTextW(g_hNextBtn, L"&Next >");

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"Welcome to SecureXP Setup Wizard", WS_VISIBLE|WS_CHILD, 20, 20, 440, 40, hWnd, NULL, NULL, NULL);
                HFONT hTitleFont = CreateFontW(18, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, FALSE);

                HWND hDesc = CreateWindowExW(0, L"STATIC", L"This wizard will install SecureXP Antivirus Pro on your computer.\n\nIt is strongly recommended that you close all other Windows applications before continuing.\n\nClick Next to continue.", WS_VISIBLE|WS_CHILD, 20, 75, 440, 150, hWnd, NULL, NULL, NULL);
                SendMessage(hDesc, WM_SETFONT, (WPARAM)hFont, FALSE);
            }
            else if (step == STEP_EULA) {
                EnableWindow(g_hBackBtn, TRUE);
                EnableWindow(g_hNextBtn, FALSE); 

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"License Agreement", WS_VISIBLE|WS_CHILD, 20, 10, 440, 20, hWnd, NULL, NULL, NULL);
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, FALSE);

                HWND hSub = CreateWindowExW(0, L"STATIC", L"Please read the following license agreement carefully.", WS_VISIBLE|WS_CHILD, 20, 30, 440, 20, hWnd, NULL, NULL, NULL);
                SendMessage(hSub, WM_SETFONT, (WPARAM)hFont, FALSE);

                std::string eulaText = LoadResourceText(102);
                std::wstring wEula = AnsiToWide(eulaText);
                if (wEula.empty()) {
                    wEula = L"SecureXP Antivirus Pro License Agreement\n\n1. Grant of License: SecureXP grants you a non-exclusive license to use this software on a single computer system.\n\n2. Restrictions: You may not reverse-engineer, decompile, or disassemble this security software.\n\n3. Liability: The authors shall not be held liable for any damages resulting from the use or misuse of this software.";
                }
                g_hEulaEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", wEula.c_str(), WS_VISIBLE|WS_CHILD|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|ES_READONLY, 20, 55, 450, 180, hWnd, NULL, NULL, NULL);
                SendMessage(g_hEulaEdit, WM_SETFONT, (WPARAM)hFont, FALSE);

                g_hEulaRadioDisAgree = CreateWindowExW(0, L"BUTTON", L"I do not accept the agreement", WS_VISIBLE|WS_CHILD|BS_AUTORADIOBUTTON, 20, 245, 400, 20, hWnd, (HMENU)201, NULL, NULL);
                g_hEulaRadioAgree = CreateWindowExW(0, L"BUTTON", L"I accept the agreement", WS_VISIBLE|WS_CHILD|BS_AUTORADIOBUTTON, 20, 275, 400, 20, hWnd, (HMENU)202, NULL, NULL);
                SendMessage(g_hEulaRadioDisAgree, WM_SETFONT, (WPARAM)hFont, FALSE);
                SendMessage(g_hEulaRadioAgree, WM_SETFONT, (WPARAM)hFont, FALSE);
                SendMessage(g_hEulaRadioDisAgree, BM_SETCHECK, BST_CHECKED, 0);
            }
            else if (step == STEP_DIRECTORY) {
                EnableWindow(g_hBackBtn, TRUE);
                EnableWindow(g_hNextBtn, TRUE);

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"Select Destination Location", WS_VISIBLE|WS_CHILD, 20, 15, 440, 25, hWnd, NULL, NULL, NULL);
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, FALSE);

                HWND hSub = CreateWindowExW(0, L"STATIC", L"Where should SecureXP be installed?", WS_VISIBLE|WS_CHILD, 20, 45, 440, 20, hWnd, NULL, NULL, NULL);
                SendMessage(hSub, WM_SETFONT, (WPARAM)hFont, FALSE);

                g_hEditPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_InstallPath, WS_VISIBLE|WS_CHILD|ES_AUTOHSCROLL, 20, 85, 360, 24, hWnd, NULL, NULL, NULL);
                SendMessage(g_hEditPath, WM_SETFONT, (WPARAM)hFont, FALSE);

                g_hBrowseBtn = CreateWindowExW(0, L"BUTTON", L"Browse...", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 390, 85, 80, 24, hWnd, (HMENU)203, NULL, NULL);
                SendMessage(g_hBrowseBtn, WM_SETFONT, (WPARAM)hFont, FALSE);
            }
            else if (step == STEP_OPTIONS) {
                EnableWindow(g_hBackBtn, TRUE);
                EnableWindow(g_hNextBtn, TRUE);

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"Select Additional Tasks", WS_VISIBLE|WS_CHILD, 20, 15, 440, 25, hWnd, NULL, NULL, NULL);
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, FALSE);

                HWND hSub = CreateWindowExW(0, L"STATIC", L"Select additional tasks you would like Setup to perform:", WS_VISIBLE|WS_CHILD, 20, 45, 440, 20, hWnd, NULL, NULL, NULL);
                SendMessage(hSub, WM_SETFONT, (WPARAM)hFont, FALSE);

                g_hCheckDesktop = CreateWindowExW(0, L"BUTTON", L"Create a desktop shortcut", WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX, 40, 85, 400, 20, hWnd, NULL, NULL, NULL);
                g_hCheckStartMenu = CreateWindowExW(0, L"BUTTON", L"Create a Start Menu folder shortcut", WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX, 40, 115, 400, 20, hWnd, NULL, NULL, NULL);
                
                SendMessage(g_hCheckDesktop, WM_SETFONT, (WPARAM)hFont, FALSE);
                SendMessage(g_hCheckStartMenu, WM_SETFONT, (WPARAM)hFont, FALSE);
                
                SendMessage(g_hCheckDesktop, BM_SETCHECK, g_CreateDesktopShortcut ? BST_CHECKED : BST_UNCHECKED, 0);
                SendMessage(g_hCheckStartMenu, BM_SETCHECK, g_CreateStartMenuShortcut ? BST_CHECKED : BST_UNCHECKED, 0);
            }
            else if (step == STEP_READY) {
                EnableWindow(g_hBackBtn, TRUE);
                EnableWindow(g_hNextBtn, TRUE);
                SetWindowTextW(g_hNextBtn, L"&Install");

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"Ready to Install", WS_VISIBLE|WS_CHILD, 20, 15, 440, 25, hWnd, NULL, NULL, NULL);
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, FALSE);

                HWND hSub = CreateWindowExW(0, L"STATIC", L"Setup is now ready to begin installing SecureXP on your computer.", WS_VISIBLE|WS_CHILD, 20, 45, 440, 20, hWnd, NULL, NULL, NULL);
                SendMessage(hSub, WM_SETFONT, (WPARAM)hFont, FALSE);

                std::wstring summary = L"Click Install to continue with the installation, or click Back to review settings.\n\n";
                summary += L"Destination Location:\n  " + std::wstring(g_InstallPath) + L"\n\n";
                summary += L"Selected Tasks:\n";
                if (g_CreateDesktopShortcut) summary += L"  - Create a desktop shortcut\n";
                if (g_CreateStartMenuShortcut) summary += L"  - Create a Start Menu folder shortcut\n";

                HWND hSummary = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", summary.c_str(), WS_VISIBLE|WS_CHILD|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|ES_READONLY, 20, 75, 450, 180, hWnd, NULL, NULL, NULL);
                SendMessage(hSummary, WM_SETFONT, (WPARAM)hFont, FALSE);
            }
            else if (step == STEP_INSTALLING) {
                EnableWindow(g_hBackBtn, FALSE);
                EnableWindow(g_hNextBtn, FALSE);
                EnableWindow(g_hCancelBtn, FALSE);

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"Installing SecureXP", WS_VISIBLE|WS_CHILD, 20, 15, 440, 25, hWnd, NULL, NULL, NULL);
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, FALSE);

                g_hStatusText = CreateWindowExW(0, L"STATIC", L"Initializing security setup system...", WS_VISIBLE|WS_CHILD, 20, 60, 440, 20, hWnd, NULL, NULL, NULL);
                SendMessage(g_hStatusText, WM_SETFONT, (WPARAM)hFont, FALSE);

                g_hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_VISIBLE|WS_CHILD, 20, 90, 450, 25, hWnd, NULL, NULL, NULL);
                SendMessage(g_hProgressBar, PBM_SETSTEP, (WPARAM)1, 0);
                SendMessage(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

                UpdateWindow(hWnd);

                InstallParams* params = new InstallParams();
                params->hwnd = hWnd;
                wcscpy_s(params->installPath, MAX_PATH, g_InstallPath);
                params->desktopShortcut = g_CreateDesktopShortcut;
                params->startMenuShortcut = g_CreateStartMenuShortcut;

                CreateThread(NULL, 0, InstallThread, params, 0, NULL);
            }
            else if (step == STEP_FINISH) {
                EnableWindow(g_hBackBtn, FALSE);
                EnableWindow(g_hNextBtn, TRUE);
                EnableWindow(g_hCancelBtn, TRUE);
                SetWindowTextW(g_hNextBtn, L"&Finish");

                HWND hTitle = CreateWindowExW(0, L"STATIC", L"Completing the SecureXP Setup Wizard", WS_VISIBLE|WS_CHILD, 20, 20, 440, 40, hWnd, NULL, NULL, NULL);
                HFONT hTitleFont = CreateFontW(18, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, FALSE);

                HWND hDesc = CreateWindowExW(0, L"STATIC", L"Setup has finished installing SecureXP Antivirus Pro on your computer.\n\nClick Finish to exit the wizard.", WS_VISIBLE|WS_CHILD, 20, 80, 440, 100, hWnd, NULL, NULL, NULL);
                SendMessage(hDesc, WM_SETFONT, (WPARAM)hFont, FALSE);
            }
            break;
        }
        case WM_USER + 101: {
            g_CurrentStep = STEP_FINISH;
            PostMessage(hWnd, WM_USER + 100, 0, STEP_FINISH);
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);

            if (wmId == 203) { 
                std::wstring folder = BrowseInstallFolder(hWnd);
                if (!folder.empty()) {
                    wcsncpy(g_InstallPath, folder.c_str(), MAX_PATH - 1);
                    SetWindowTextW(g_hEditPath, g_InstallPath);
                }
            }
            else if (wmId == 202) { 
                if (g_CurrentStep == STEP_EULA) EnableWindow(g_hNextBtn, TRUE);
            }
            else if (wmId == 201) { 
                if (g_CurrentStep == STEP_EULA) EnableWindow(g_hNextBtn, FALSE);
            }
            else if (wmId == 103) { 
                if (MessageBoxW(hWnd, L"Are you sure you want to cancel Setup?", L"SecureXP Setup", MB_YESNO|MB_ICONQUESTION) == IDYES) {
                    DestroyWindow(hWnd);
                }
            }
            else if (wmId == 102) { 
                if (g_CurrentStep == STEP_WELCOME) {
                    g_CurrentStep = STEP_EULA;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_EULA);
                }
                else if (g_CurrentStep == STEP_EULA) {
                    g_CurrentStep = STEP_DIRECTORY;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_DIRECTORY);
                }
                else if (g_CurrentStep == STEP_DIRECTORY) {
                    GetWindowTextW(g_hEditPath, g_InstallPath, MAX_PATH);
                    g_CurrentStep = STEP_OPTIONS;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_OPTIONS);
                }
                else if (g_CurrentStep == STEP_OPTIONS) {
                    g_CreateDesktopShortcut = (SendMessage(g_hCheckDesktop, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    g_CreateStartMenuShortcut = (SendMessage(g_hCheckStartMenu, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    
                    g_CurrentStep = STEP_READY;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_READY);
                }
                else if (g_CurrentStep == STEP_READY) {
                    g_CurrentStep = STEP_INSTALLING;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_INSTALLING);
                }
                else if (g_CurrentStep == STEP_FINISH) {
                    DestroyWindow(hWnd);
                }
            }
            else if (wmId == 101) { 
                if (g_CurrentStep == STEP_EULA) {
                    g_CurrentStep = STEP_WELCOME;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_WELCOME);
                }
                else if (g_CurrentStep == STEP_DIRECTORY) {
                    g_CurrentStep = STEP_EULA;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_EULA);
                }
                else if (g_CurrentStep == STEP_OPTIONS) {
                    g_CurrentStep = STEP_DIRECTORY;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_DIRECTORY);
                }
                else if (g_CurrentStep == STEP_READY) {
                    g_CurrentStep = STEP_OPTIONS;
                    PostMessage(hWnd, WM_USER + 100, 0, STEP_OPTIONS);
                }
            }
            break;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            break;
        }
        default: return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); 
    wc.lpszClassName = L"SecureXPSetupWizardClass";
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(101)); 
    wc.hIconSm = LoadIconW(hInst, MAKEINTRESOURCEW(101));
    RegisterClassExW(&wc);

    HWND hWnd = CreateWindowExW(0, L"SecureXPSetupWizardClass", L"SecureXP Pro - Setup Wizard", 
                           (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE), 
                           CW_USEDEFAULT, CW_USEDEFAULT, 500, 395, NULL, NULL, hInst, NULL);

    if (!hWnd) return 0;
    g_hMainWnd = hWnd;
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while(GetMessageW(&msg, NULL, 0, 0)) { 
        TranslateMessage(&msg); 
        DispatchMessageW(&msg); 
    }
    return (int)msg.wParam;
}