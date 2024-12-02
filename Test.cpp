#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <csignal>
#include <ctime>
#include <condition_variable>
#include <mutex>


#pragma comment(lib, "ws2_32.lib")
HHOOK hookHandle;
bool monitorProcesses = true;
bool serverRunning = true;
std::condition_variable cvStartService;
std::mutex mtxStartService;
bool serviceStarted = false;

std::string getCurrentTime() {
    std::time_t now = std::time(nullptr);
    struct tm timeInfo;
    char buffer[20];

    // Use localtime_s for safety
    if (localtime_s(&timeInfo, &now) == 0) {
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);
        return buffer;
    } else {
        return "Error getting time";
    }
}

// Logger function
void logMessage(const std::string& message, const std::string& level = "INFO") {
    std::ofstream logFile("log.txt", std::ios::app); // Append mode
    if (logFile.is_open()) {
        logFile << "[" << getCurrentTime() << "] [" << level << "] " << message << std::endl;
    }
    logFile.close();
}
void SignalHandlerNew(int signal) {
    monitorProcesses = false;
    std::cout << "Service stopped." << std::endl;
    logMessage("Service stopped.", "INFO");
    std::exit(signal);
}
void HideTaskbar() {
    HWND hTaskbar = FindWindow(L"Shell_TrayWnd", NULL);
    if (hTaskbar) {
        ShowWindow(hTaskbar, SW_HIDE);
        std::cout << "Taskbar hidden." << std::endl;
        logMessage("Taskbar hidden.", "INFO");
    }
    else {
        std::cerr << "Failed to find taskbar." << std::endl;
        logMessage("Failed to find taskbar.", "ERROR");
    }
}

void ShowTaskbar() {
    HWND hTaskbar = FindWindow(L"Shell_TrayWnd", NULL);
    if (hTaskbar) {
        ShowWindow(hTaskbar, SW_SHOW);
        std::cout << "Taskbar shown." << std::endl;
        logMessage("Taskbar shown.", "INFO");
    }
    else {
        std::cerr << "Failed to find taskbar." << std::endl;
        logMessage("Failed to find taskbar.", "ERROR");
    }
}

void HTTPServer() {
    WSADATA wsaData;
    SOCKET listeningSocket = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock." << std::endl;
        logMessage("Failed to initialize Winsock.", "ERROR");
        return;
    }

    listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listeningSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket." << std::endl;
        logMessage("Failed to create socket.", "ERROR");
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(3000);

    if (bind(listeningSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed." << std::endl;
        logMessage("Bind failed.", "ERROR");
        closesocket(listeningSocket);
        WSACleanup();
        return;
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed." << std::endl;
        logMessage("Listen failed.", "ERROR");
        closesocket(listeningSocket);
        WSACleanup();
        return;
    }

    std::cout << "HTTP server running on port 3000..." << std::endl;

    while (serverRunning) {
        SOCKET clientSocket = accept(listeningSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed." << std::endl;
            logMessage("Accept failed.", "ERROR");
            continue;
        }

        char buffer[1024] = { 0 };
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived > 0) {
            std::string request(buffer, bytesReceived);

            // Extract Origin header
            std::string origin = "https://localhost"; // Default value
            auto originPos = request.find("Origin: ");
            if (originPos != std::string::npos) {
                auto endLine = request.find("\r\n", originPos);
                origin = request.substr(originPos + 8, endLine - (originPos + 8));
            }

            // Build headers with dynamic Access-Control-Allow-Origin
            std::string headers = "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: " + origin + "\r\n"
                "Access-Control-Allow-Credentials: true\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type\r\n";

            if (request.find("OPTIONS") != std::string::npos) {
                // Handle preflight requests
                headers += "\r\n";
                send(clientSocket, headers.c_str(), headers.length(), 0);
            }
            else if (request.find("GET /startService") != std::string::npos) {
                std::cout << "Start Service" << std::endl;
                logMessage("Start Service", "INFO");
                std::string jsonResponse = R"({"message":"Service started successfully"})";

                {
                    std::lock_guard<std::mutex> lock(mtxStartService);
                    serviceStarted = true;
                }
                cvStartService.notify_one(); // Notify the main thread to start the service

                std::string response = headers + "\r\n" + jsonResponse;
                send(clientSocket, response.c_str(), response.length(), 0);
            }
            else if (request.find("GET /stopService") != std::string::npos) {
                std::cout << "Stop Service" << std::endl;
                std::string jsonResponse = R"({"message":"Service stopped successfully"})";
                logMessage(R"({"message":"Service stopped successfully"})", "INFO");
                std::string response = headers + "\r\n" + jsonResponse;
                send(clientSocket, response.c_str(), response.length(), 0);
                serverRunning = false; // Stop the server
                ShowTaskbar();
                SignalHandlerNew(SIGINT); // Simulate Ctrl+C
            }
            else {
                // Handle unknown requests
                std::string jsonResponse = R"({"error":"Invalid endpoint"})";
                logMessage(R"({"error":"Invalid endpoint"})", "ERROR");
                std::string response = headers + "\r\n" + jsonResponse;
                send(clientSocket, response.c_str(), response.length(), 0);
            }
        }
        closesocket(clientSocket);
    }

    closesocket(listeningSocket);
    WSACleanup();
}

void KillProcesses(const std::vector<std::wstring>& processNames) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot of processes." << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            for (const auto& targetName : processNames) {
                if (_wcsicmp(pe32.szExeFile, targetName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        if (TerminateProcess(hProcess, 0)) {
                            std::wcout << L"Terminated process: " << targetName << std::endl;
                            logMessage("Processes terminated", "INFO");
                        }
                        else {
                            std::wcout << L"Failed to terminate process: " << targetName << std::endl;
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        } while (Process32Next(hSnap, &pe32));
    }
    else {
        std::cerr << "Failed to retrieve process list." << std::endl;
    }

    CloseHandle(hSnap);
}


void MonitorProcesses(const std::vector<std::wstring>& processNames) {
    while (monitorProcesses) {
        KillProcesses(processNames);
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Check every second
    }
}

void SignalHandler(int signal) {
    ShowTaskbar();
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::exit(signal); // Exit after handling
}

// RAII wrapper to ensure taskbar visibility
struct TaskbarGuard {
    TaskbarGuard() { HideTaskbar(); }
    ~TaskbarGuard() { ShowTaskbar(); }
};
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbStruct = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // Intercept key events
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            // Block Alt+Tab
            if (kbStruct->vkCode == VK_TAB && GetAsyncKeyState(VK_MENU) & 0x8000) {
                std::cout << "Alt+Tab combination intercepted!" << std::endl;
                logMessage("Alt+Tab combination intercepted!", "INFO");
                return 1; // Block the key combination
            }

            // Block Ctrl+Alt+Tab
            if (kbStruct->vkCode == VK_TAB &&
                GetAsyncKeyState(VK_CONTROL) & 0x8000 &&
                GetAsyncKeyState(VK_MENU) & 0x8000) {
                std::cout << "Ctrl+Alt+Tab combination intercepted!" << std::endl;
                logMessage("Ctrl+Alt+Tab combination intercepted!", "INFO");
                return 1; // Block the key combination
            }
            // Block Alt+Esc
            if (kbStruct->vkCode == VK_ESCAPE && (GetAsyncKeyState(VK_MENU) & 0x8000)) {
                std::cout << "Alt+Esc combination intercepted!" << std::endl;
                logMessage("Alt+Esc combination intercepted!", "INFO");
                return 1; // Block the key combination
            }

            // Block Ctrl+Tab
            if (kbStruct->vkCode == VK_TAB && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
                std::cout << "Ctrl+Tab combination intercepted!" << std::endl; 
                logMessage("Ctrl+Tab combination intercepted!", "INFO");
                return 1; // Block the key combination
            }
            if (kbStruct->vkCode == VK_DELETE &&
                (GetAsyncKeyState(VK_CONTROL) & 0x8000) &&
                (GetAsyncKeyState(VK_MENU) & 0x8000)) {
                std::cout << "Ctrl+Alt+Del combination intercepted!" << std::endl;
                logMessage("Ctrl+Alt+Del combination intercepted!", "INFO");
                return 1;
            }
            if (kbStruct->vkCode == VK_ESCAPE &&
                (GetAsyncKeyState(VK_CONTROL) & 0x8000) &&
                (GetAsyncKeyState(VK_SHIFT) & 0x8000)) {
                std::cout << "Ctrl+Shift+Esc combination intercepted!" << std::endl;
                logMessage("Ctrl+Shift+Esc combination intercepted!", "INFO");
                return 1;
            }
            bool isWindowsKeyDown = (GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000);

            // Windows + Tab
            if (isWindowsKeyDown && kbStruct->vkCode == VK_TAB) {
                std::cout << "Windows+Tab combination intercepted!" << std::endl;
                return 1;
            }

            // Windows + D (Show/Hide Desktop)
            if (isWindowsKeyDown && kbStruct->vkCode == 'D') {
                std::cout << "Windows+D combination intercepted!" << std::endl;
                return 1;
            }

            // Windows + E (Open File Explorer)
            if (isWindowsKeyDown && kbStruct->vkCode == 'E') {
                std::cout << "Windows+E combination intercepted!" << std::endl;
                return 1;
            }

            // Windows + R (Run dialog)
            if (isWindowsKeyDown && kbStruct->vkCode == 'R') {
                std::cout << "Windows+R combination intercepted!" << std::endl;
                return 1;
            }

            // Windows + L (Lock computer)
            if (isWindowsKeyDown && kbStruct->vkCode == 'L') {
                std::cout << "Windows+L combination intercepted!" << std::endl;
                return 1;
            }

            // Windows + P (Project/Presentation Display)
            if (isWindowsKeyDown && kbStruct->vkCode == 'P') {
                std::cout << "Windows+P combination intercepted!" << std::endl;
                return 1;
            }

            // Windows + X (Quick Link menu)
            if (isWindowsKeyDown && kbStruct->vkCode == 'X') {
                std::cout << "Windows+X combination intercepted!" << std::endl;
                return 1;
            }

            // Windows key alone
            if (kbStruct->vkCode == VK_LWIN || kbStruct->vkCode == VK_RWIN) {
                std::cout << "Windows key intercepted!" << std::endl;
                logMessage("Windows key intercepted!", "INFO");
                return 1;
            }
        }
    }

    return CallNextHookEx(hookHandle, nCode, wParam, lParam);
}

void StartService(const std::vector<std::wstring>& processesToKill) {
    // Start the monitoring thread
    std::thread monitorThread(MonitorProcesses, processesToKill);
    monitorThread.detach(); // Allow monitorThread to run independently

    // Install the keyboard hook
    hookHandle = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (hookHandle == NULL) {
        std::cerr << "Failed to install keyboard hook" << std::endl;
        return;
    }

    std::cout << "Keyboard hook installed." << std::endl;
    logMessage("Keyboard hook installed.", "INFO");

    // Hide the taskbar
    HideTaskbar();
}
//use instead of main() to hide the terminal that appears, also in properties>linker>system ,change to SUBSYSTEM/Windows
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    std::signal(SIGINT, SignalHandler);  // Handle Ctrl+C
    std::signal(SIGTERM, SignalHandler); // Handle termination signals
    std::vector<std::wstring> processesToKill = {
        L"notepad.exe",
        L"calc.exe",
        L"skype.exe",
        L"mstsc.exe",
        L"notepad++.exe" // Example: Add process names here
    };
    // Start the HTTP server in a separate thread
    std::thread serverThread(HTTPServer);
    serverThread.detach(); // Allow serverThread to run independently

    // Wait for the /startService request
    {
        std::unique_lock<std::mutex> lock(mtxStartService);
        cvStartService.wait(lock, [] { return serviceStarted; });
    }

    // Start the service after /startService is received
    StartService(processesToKill);

    // Message loop for keyboard hook
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Unhook the keyboard hook when exiting
    UnhookWindowsHookEx(hookHandle);
    return 0;
}
