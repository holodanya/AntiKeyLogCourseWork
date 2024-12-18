#include "Resource.h"

#include <windows.h>           // Для використання Windows API
#include <string>
#include <vector>
#include <tlhelp32.h>          // Для створення знімків процесів/потоків
#include <psapi.h>             // Для отримання інформації про процеси
#pragma comment(lib, "psapi.lib")
#include <dwmapi.h>            // Для роботи з композицією вікон Desktop Window Manager
#pragma comment(lib, "Dwmapi.lib")
#include <richedit.h>          // Для використання RichEdit-контролів


// Вказівка на використання сучасних контролів
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")


HINSTANCE hInst;                                                    // Дескриптор екземпляра додатку
CHAR szTitle[MAX_LOADSTRING] = "AntiKeyLogger";                     // Заголовок вікна
CHAR szWindowClass[MAX_LOADSTRING] = "AntiKeyLoggerWindow";         // Ім'я класу вікна

HWND hListBox, hRichEdit, hTerminateButton, hListLabel, hOpenLocButton, hScanButton; // Глобальні хендли елементів інтерфейсу

COLORREF BackgroundCLR = RGB(200, 220, 255);                        // Колір фону
HBRUSH hBrushBackground = CreateSolidBrush(BackgroundCLR);          // Пензель для фону

std::vector<std::pair<std::string, DWORD>> suspiciousProcesses;      // Вектор підозрілих процесів (ім'я, PID)
std::string detailedInfo;                                            // Рядок для детальної інформації про процес
DWORD selectedPID = 0;                                               // Обраний PID процесу

// Список довірених процесів, які не варто розглядати як підозрілі
const std::vector<std::string> trustedProcesses = {
    "svchost.exe", "lsass.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
    "spoolsv.exe", "audiodg.exe", "SearchIndexer.exe", "msedge.exe",
    "msedgewebview2.exe", "devenv.exe"
};

// Список підозрілих функцій, які можуть використовуватися кейлогерами для перехоплення клавіш
const std::vector<const char*> suspiciousFunctions = {
    "SetWindowsHookExA", "GetAsyncKeyState", "GetKeyState"
};


// Прототипи функцій
ATOM MyRegisterClass(HINSTANCE hInstance);                           // Реєстрація класу вікна
BOOL InitInstance(HINSTANCE, int);                                   // Ініціалізація екземпляра програми
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);                // Віконна процедура

std::string GetProcessPath(HANDLE hProcess);                         // Отримання шляху до файлу процесу
bool CheckExportedFunction(HANDLE hProcess, HMODULE hModule, std::string& detectedFunctions); // Перевірка наявності підозрілих функцій в модулі
void ScanProcesses();                                                // Сканування процесів для виявлення підозрілих
void UpdateProcessList(HWND hListBox);                               // Оновлення списку процесів у лістбоксі
void DisplayProcessDetails(int index);                               // Відображення детальної інформації про обраний процес

void CreateElements(HWND hWnd);                                      // Створення елементів інтерфейсу
HBRUSH SetControlColor(WPARAM wParam, HBRUSH hBrush);                // Налаштування кольорів контролів
void OnListBoxSelectionChange();                                     // Обробка зміни вибору у лістбоксі
void OnButtonTerminate(HWND hWnd);                                   // Обробка натискання кнопки завершення процесу
void OnButtonOpenLocation();                                         // Обробка натискання кнопки відкриття розташування файлу процесу
void OnButtonScan();                                                 // Обробка натискання кнопки сканування


// Основна функція програми
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine,
    int nCmdShow)
{
    LoadLibrary(TEXT("Msftedit.dll")); // Завантаження бібліотеки для RichEdit-контролу
    hInst = hInstance;                 // Збереження екземпляра додатку

    // Реєстрація класу вікна
    MyRegisterClass(hInstance);

    // Створення та ініціалізація вікна програми
    if (!InitInstance(hInstance, nCmdShow))
    {
        return FALSE;
    }

    MSG msg;
    // Цикл повідомлень
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

// Реєстрація класу вікна
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex; // Структура для інформації про клас
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;              // Стиль вікна
    wcex.lpfnWndProc = (WNDPROC)WndProc;               // Віконна процедура
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;                        // Дескриптор екземпляра
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ANTIKEYLOGCOURSEWORK)); // Іконка вікна
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);        // Курсор миші
    wcex.hbrBackground = hBrushBackground;             // Фон вікна
    wcex.lpszMenuName = NULL;                          // Меню відсутнє
    wcex.lpszClassName = szWindowClass;                // Ім'я класу вікна
    wcex.hIconSm = NULL;

    return RegisterClassEx(&wcex);                     // Реєстрація класу
}

// Створення вікна додатку та збереження його дескриптора у hInst
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    HWND hWnd;
    hInst = hInstance; // Збереження дескриптора екземпляра

    // Створення вікна
    hWnd = CreateWindow(szWindowClass,
        szTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,  // Положення по Х
        0,              // Положення по Y
        800,            // Ширина вікна
        575,            // Висота вікна
        NULL,           // Батьківське вікно відсутнє
        NULL,           // Меню відсутнє
        hInstance,
        NULL);          // Додаткові параметри

    if (!hWnd) // Якщо не вдалося створити вікно
    {
        return FALSE;
    }

    // Налаштування кольору заголовку через DWM
    DwmSetWindowAttribute(hWnd, DWMWA_CAPTION_COLOR, &BackgroundCLR, sizeof(BackgroundCLR));

    ShowWindow(hWnd, nCmdShow);  // Показати вікно
    UpdateWindow(hWnd);          // Оновити вікно
    return TRUE;
}

// Віконна процедура для обробки повідомлень
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {

    switch (message) {
    case WM_CREATE: {
        // Створення елементів інтерфейсу, сканування процесів та оновлення списку
        CreateElements(hWnd);
        ScanProcesses();
        UpdateProcessList(hListBox);
    }
    break;

    case WM_CTLCOLORLISTBOX: {
        // Зміна кольору фонів контролів
        return (LRESULT)SetControlColor(wParam, hBrushBackground);
    }

    case WM_CTLCOLORSTATIC: {
        // Зміна кольору статичних текстів
        return (LRESULT)SetControlColor(wParam, (HBRUSH)GetStockObject(NULL_BRUSH));
    }

    case WM_COMMAND: {
        // Обробка команд від контролів
        switch (LOWORD(wParam)) {
        case LISTBOX_ID:
            OnListBoxSelectionChange();
            break;

        case BUTTON_TERMINATE:
            OnButtonTerminate(hWnd);
            break;

        case BUTTON_OPEN_LOCATION:
            OnButtonOpenLocation();
            break;

        case BUTTON_SCAN:
            OnButtonScan();
            break;

        default:
            break;
        }
    }
                   break;

    case WM_DESTROY:
        // Звільнення ресурсів та завершення роботи програми
        PostQuitMessage(0);
        DeleteObject(hBrushBackground);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}


// Отримання шляху до процесу
std::string GetProcessPath(HANDLE hProcess) {
    char processPath[MAX_PATH] = { 0 };
    // Отримання шляху до файлу процесу
    if (GetModuleFileNameExA(hProcess, NULL, processPath, MAX_PATH)) {
        return std::string(processPath);
    }
    return "Unknown";
}

// Перевірка експорту функцій модуля на наявність підозрілих функцій
bool CheckExportedFunction(HANDLE hProcess, HMODULE hModule, std::string& detectedFunctions) {
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;

    // Читання DOS-заголовку
    if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(dosHeader), &bytesRead) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    IMAGE_NT_HEADERS ntHeaders;
    LPVOID ntHeadersAddr = (LPBYTE)hModule + dosHeader.e_lfanew;

    // Читання NT-заголовку
    if (!ReadProcessMemory(hProcess, ntHeadersAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    DWORD exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) return false;

    IMAGE_EXPORT_DIRECTORY exportDir;
    LPVOID exportDirAddr = (LPBYTE)hModule + exportDirRVA;

    // Читання директорії експорту
    if (!ReadProcessMemory(hProcess, exportDirAddr, &exportDir, sizeof(exportDir), &bytesRead)) {
        return false;
    }

    // Масив для збереження індексів імен функцій
    std::vector<DWORD> funcNames(exportDir.NumberOfNames);
    LPVOID funcNamesAddr = (LPBYTE)hModule + exportDir.AddressOfNames;

    // Отримання імен функцій, що експортуються
    if (!ReadProcessMemory(hProcess, funcNamesAddr, funcNames.data(), funcNames.size() * sizeof(DWORD), &bytesRead)) {
        return false;
    }

    bool found = false;

    // Перевірка кожної назви функції
    for (DWORD i = 0; i < exportDir.NumberOfNames; ++i) {
        char functionNameBuffer[256] = { 0 };
        LPVOID functionNameAddr = (LPBYTE)hModule + funcNames[i];

        if (ReadProcessMemory(hProcess, functionNameAddr, functionNameBuffer, sizeof(functionNameBuffer), &bytesRead)) {
            // Порівняння з підозрілими функціями
            for (const auto& suspiciousFunc : suspiciousFunctions) {
                if (_stricmp(functionNameBuffer, suspiciousFunc) == 0) {
                    detectedFunctions += "    [!] Function detected: " + std::string(functionNameBuffer) + "\n";
                    found = true;
                }
            }
        }
    }

    return found;
}

// Сканування процесів для виявлення підозрілих
void ScanProcesses() {
    suspiciousProcesses.clear();
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Перебірка кожного процесу у системі
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            std::string processName = pe32.szExeFile;
            // Пропуск довірених процесів
            if (std::find(trustedProcesses.begin(), trustedProcesses.end(), processName) != trustedProcesses.end()) {
                continue;
            }
            if (processName.find("ServiceHub") != std::string::npos) { continue; }

            // Відкриття процесу
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HMODULE hMods[1024];
                DWORD cbNeeded;

                std::string processPath = GetProcessPath(hProcess);
                // Пропуск системних і програмних шляхів, де процеси не є підозрілими
                if (processPath.find("C:\\Windows\\System32") != std::string::npos ||
                    processPath.find("C:\\Windows\\SysWOW64") != std::string::npos ||
                    processPath.find("C:\\Program Files\\Microsoft Visual Studio") != std::string::npos ||
                    processPath.find("C:\\ProgramFiles\\WindowsApps") != std::string::npos) {
                    CloseHandle(hProcess);
                    continue;
                }

                // Перебірка завантажених модулів процесу
                if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
                        char moduleName[MAX_PATH];
                        if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                            // Якщо процес використовує user32.dll, вважаємо його потенційно підозрілим
                            if (_stricmp(moduleName, "user32.dll") == 0) {
                                suspiciousProcesses.emplace_back(processName, pe32.th32ProcessID);
                                break;
                            }
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
}

// Оновлення списку процесів у лістбоксі
void UpdateProcessList(HWND hListBox) {
    SendMessage(hListBox, LB_RESETCONTENT, 0, 0);

    for (const auto& proc : suspiciousProcesses) {
        std::string processEntry = proc.first + " (PID: " + std::to_string(proc.second) + ")";
        SendMessageA(hListBox, LB_ADDSTRING, 0, (LPARAM)processEntry.c_str());
    }
}

// Відображення деталей обраного процесу
void DisplayProcessDetails(int index) {
    if (index < 0 || index >= (int)suspiciousProcesses.size()) return;

    auto& processInfo = suspiciousProcesses[index];
    selectedPID = processInfo.second;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processInfo.second);
    if (hProcess) {
        std::string processPath = GetProcessPath(hProcess);
        std::string detectedFunctions;

        // Формування детальної інформації про процес
        detailedInfo = "Details for: " + processInfo.first + " (PID: " + std::to_string(processInfo.second) + ")\n";
        detailedInfo += "Location: " + processPath + "\n";
        detailedInfo += "Module: user32.dll\n";

        HMODULE hMods[1024];
        DWORD cbNeeded;
        // Перевірка модулів процесу
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
                char moduleName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                    // Перевірка user32.dll на підозрілі функції
                    if (_stricmp(moduleName, "user32.dll") == 0) {
                        CheckExportedFunction(hProcess, hMods[i], detectedFunctions);
                    }
                }
            }
        }

        // Додавання інформації про знайдені підозрілі функції
        detailedInfo += detectedFunctions.empty() ? "No suspicious functions detected.\n" : detectedFunctions;

        // Вивід інформації у RichEdit
        SetWindowTextA(hRichEdit, detailedInfo.c_str());
        CloseHandle(hProcess);
    }
}

// Створення елементів інтерфейсу в основному вікні
void CreateElements(HWND hWnd) {

    // Мітка над списком
    hListLabel = CreateWindow("STATIC", "Potential Threats",
        WS_CHILD | WS_VISIBLE, 10, 5, 400, 20,
        hWnd, NULL, hInst, NULL);

    // Лістбокс для відображення підозрілих процесів
    hListBox = CreateWindow("LISTBOX", NULL,
        WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY | WS_VSCROLL,
        10, 30, 300, 450, hWnd, (HMENU)LISTBOX_ID, hInst, NULL);

    // RichEdit для відображення детальної інформації
    hRichEdit = CreateWindow("RICHEDIT50W", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_SUNKEN | ES_READONLY,
        320, 30, 450, 450,
        hWnd, (HMENU)IDC_RICHEDIT, hInst, NULL);

    // Кнопка для завершення процесу
    hTerminateButton = CreateWindow("BUTTON", "Terminate Process",
        WS_CHILD | WS_VISIBLE,
        395, 500, 150, 30,
        hWnd, (HMENU)BUTTON_TERMINATE, hInst, NULL);

    // Кнопка для відкриття розташування файлу процесу
    hOpenLocButton = CreateWindow("BUTTON", "Open Location",
        WS_CHILD | WS_VISIBLE,
        555, 500, 150, 30,
        hWnd, (HMENU)BUTTON_OPEN_LOCATION, hInst, NULL);

    // Кнопка для сканування процесів
    hScanButton = CreateWindow("BUTTON", "Scan for Processes",
        WS_CHILD | WS_VISIBLE,
        10, 500, 300, 30,
        hWnd, (HMENU)BUTTON_SCAN, hInst, NULL);
}


// Налаштування кольорів для контролів
HBRUSH SetControlColor(WPARAM wParam, HBRUSH hBrush) {
    HDC hdc = (HDC)wParam;
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(0, 0, 128));
    return hBrush;
}

// Обробка зміни вибору у лістбоксі
void OnListBoxSelectionChange() {
    int selectedIndex = (int)SendMessage(hListBox, LB_GETCURSEL, 0, 0);
    DisplayProcessDetails(selectedIndex);
}

// Завершення обраного процесу
void OnButtonTerminate(HWND hWnd) {
    if (selectedPID) {
        // Підтвердження дії користувачем
        if (MessageBox(hWnd, "Are you sure?", "Confirm", MB_YESNO) == IDYES) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, selectedPID);
            if (hProcess) {
                TerminateProcess(hProcess, 0); // Завершення процесу
                CloseHandle(hProcess);
                MessageBox(hWnd, "Terminated", "Info", MB_OK);
                ScanProcesses();
                UpdateProcessList(hListBox);
                SetWindowTextA(hRichEdit, "");
            }
        }
    }
}

// Відкриття розташування файлу процесу у провіднику
void OnButtonOpenLocation() {
    if (selectedPID) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, selectedPID);
        if (hProcess) {
            std::string processPath = GetProcessPath(hProcess);
            if (!processPath.empty()) {
                std::string command = "/select, \"" + processPath + "\"";
                ShellExecute(NULL, "open", "explorer.exe", command.c_str(), NULL, SW_SHOW);
            }
            CloseHandle(hProcess);
        }
    }
}

// Повторне сканування процесів
void OnButtonScan() {
    ScanProcesses();
    UpdateProcessList(hListBox);
    SetWindowTextA(hRichEdit, "");
}
