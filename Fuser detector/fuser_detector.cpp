#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <physicalmonitorenumerationapi.h>
#include <lowlevelmonitorconfigurationapi.h>

#include <iostream>
#include <vector>
#include <string>
#include <map>

#pragma comment(lib, "Dxva2.lib")

static const std::array<const std::wstring> KNOWN_SUSPICIOUS_VENDORS = {
    L"AOC2703",
    L"AOC3403",
    L"AUS2704",
    L"HKC2520",
    L"MSI5CA9",
    L"SAC2942"
};

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole, color);
}

std::map<std::wstring, std::vector<BYTE>> EnumerateRegistryEDIDs() {
    std::map<std::wstring, std::vector<BYTE>> registryEDIDs;

    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key.\n";

        return registryEDIDs;
    }

    DWORD index = 0;
    WCHAR subKeyName[256];

    while (true) {
        DWORD subKeyNameSize = (DWORD)(sizeof(subKeyName) / sizeof(subKeyName[0]));
        LONG ret = RegEnumKeyExW(hKey, index++, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL);

        if (ret == ERROR_NO_MORE_ITEMS || ret != ERROR_SUCCESS) {
            break;
        }

        HKEY hSubKey;
        std::wstring monitorKeyPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\") + subKeyName;
        
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, monitorKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            DWORD index2 = 0;
            WCHAR instanceName[256]{L'\0'};

            while (true) {
                DWORD instanceNameSize = (DWORD)(sizeof(instanceName) / sizeof(instanceName[0]));
                LONG ret2 = RegEnumKeyExW(hSubKey, index2++, instanceName, &instanceNameSize, NULL, NULL, NULL, NULL);

                if (ret2 == ERROR_NO_MORE_ITEMS || ret2 != ERROR_SUCCESS) {
                    break;
                }

                HKEY hInstanceKey;
                std::wstring instancePath = monitorKeyPath + L"\\" + instanceName + L"\\Device Parameters";
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, instancePath.c_str(), 0, KEY_READ, &hInstanceKey) == ERROR_SUCCESS) {
                    DWORD edidSize = 0;
                    if (RegQueryValueExW(hInstanceKey, L"EDID", NULL, NULL, NULL, &edidSize) == ERROR_SUCCESS && edidSize > 0) {
                        std::vector<BYTE> edidData(edidSize);
                        if (RegQueryValueExW(hInstanceKey, L"EDID", NULL, NULL, edidData.data(), &edidSize) == ERROR_SUCCESS) {
                            registryEDIDs[monitorKeyPath] = edidData;
                        }
                    }
                    RegCloseKey(hInstanceKey);
                }
            }
            RegCloseKey(hSubKey);
        }
    }

    RegCloseKey(hKey);
    return registryEDIDs;
}

int main() {
    std::vector<HMONITOR> hMonitors;

    if (!EnumDisplayMonitors(nullptr, nullptr, [](HMONITOR hMon, HDC, LPRECT, LPARAM pData) -> BOOL {
        auto monitors = reinterpret_cast<std::vector<HMONITOR>*>(pData);
        monitors->push_back(hMon);
        return TRUE;
        }, reinterpret_cast<LPARAM>(&hMonitors))) {
        std::cerr << "Failed to enumerate monitors\n";
        return 1;
    }

    struct MonitorInfo {
        std::wstring name;
        bool isEmulated;
        DWORD brightnessMax;
        DWORD brightnessCurrent;
    };

    std::vector<MonitorInfo> activeMonitorsInfo;

    for (auto hMon : hMonitors) {
        DWORD numPhysicalMonitors = 0;
        if (!GetNumberOfPhysicalMonitorsFromHMONITOR(hMon, &numPhysicalMonitors)) {
            std::cerr << "Failed to get number of physical monitors\n";
            continue;
        }

        std::vector<PHYSICAL_MONITOR> physicalMonitors(numPhysicalMonitors);
        if (!GetPhysicalMonitorsFromHMONITOR(hMon, numPhysicalMonitors, physicalMonitors.data())) {
            std::cerr << "Failed to get physical monitors\n";
            continue;
        }

        for (auto& pm : physicalMonitors) {
            BYTE VCP_CODE = 0x10; // Brightness code as an example
            DWORD currentVal = 0;
            DWORD maxVal = 0;
            bool isEmulated = false;

            if (!GetVCPFeatureAndVCPFeatureReply(pm.hPhysicalMonitor, VCP_CODE, nullptr, &currentVal, &maxVal)) {
                isEmulated = true;
            }

            MonitorInfo info;
            info.name = pm.szPhysicalMonitorDescription;
            info.isEmulated = isEmulated;
            info.brightnessMax = maxVal;
            info.brightnessCurrent = currentVal;
            activeMonitorsInfo.push_back(info);

            DestroyPhysicalMonitor(pm.hPhysicalMonitor);
        }
    }

    auto registryMonitors = EnumerateRegistryEDIDs();

    std::wcout << L"Regedit display list:\n";
    int suspiciousRegistryVendorQuantity = 0;
    for (auto& pair : registryMonitors) {
        for (auto& vid : KNOWN_SUSPICIOUS_VENDORS) {
            if (pair.first.find(vid) != std::wstring::npos) {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                suspiciousRegistryVendorQuantity++;
            }
        }
        std::wcout << pair.first << L"\n";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    bool activeSuspicious = false;
    for (auto& m : activeMonitorsInfo) {
        if (m.isEmulated) {
            activeSuspicious = true;
            break;
        }
    }

    int susLevel = 0;
    if (activeSuspicious) 
        susLevel++;
    
    susLevel += suspiciousRegistryVendorQuantity;

    std::wcout << L"\nCurrently active monitors:\n";
    if (activeMonitorsInfo.empty()) {
        std::wcout << L"  None\n";
    }
    else {
        for (auto& m : activeMonitorsInfo) {
            if (m.isEmulated) {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"Monitor: " << m.name;
                std::wcout << L" - suspicious (no DDC/CI support)\n";
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            else {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"Monitor: " << m.name;
                std::wcout << L" - normal behaviour (DDC/CI supported)";
                std::wcout << L" - current brightness: " << m.brightnessCurrent << L"\n";
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
        }
    }

    std::wcout << L"\nSuspicious level: ";
    
    if (susLevel > 1) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    }
    else if (susLevel > 0) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
    
    std::wcout << susLevel << L"\n";
    std::wcout << L"Reason(s):\n";
    if (activeSuspicious) {
        std::wcout << L"One of your monitors does not have DDC/CI support, which is common when using a DICHEN FUSER.\n";
    }
    if (suspiciousRegistryVendorQuantity > 0) {
        std::wcout << L"You have a total of " << suspiciousRegistryVendorQuantity << " commmon DICHEN FUSER monitors in your computer's registry.\n";
    }

    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::cout << '\n';

    system("pause");

    return 0;
}
