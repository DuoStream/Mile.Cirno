/*
 * PROJECT:   Mile.Cirno
 * FILE:      Mile.Cirno.cpp
 * PURPOSE:   Implementation for Mile.Cirno
 *
 * LICENSE:   The MIT License
 *
 * MAINTAINER: MouriNaruto (Kenji.Mouri@outlook.com)
 */

#define _WINSOCKAPI_
#define WIN32_NO_STATUS
#include <Windows.h>
#include <WinSock2.h>
#include <Psapi.h>
#include <sddl.h>
#include <hvsocket.h>

#include <Mile.Project.Version.h>

#include <Mile.Helpers.CppBase.h>

#include <dokan/dokan.h>

#include <cstdint>

#include <clocale>
#include <cstdio>
#include <cwchar>

#include <filesystem>
#include <span>
#include <chrono>
#include <vector>
#include <algorithm>
#include <string>

#include <atomic>
#include <mutex>

#include "Mile.Cirno.Core.h"
#include "Mile.Cirno.Protocol.Parser.h"

/// <summary>
/// The log components.
/// </summary>
typedef enum
{
    Nothing = 0x0,
    Errors = 0x1,
    Warnings = 0x2,
    Information = 0x4,
    DebugData = 0x8,
    Patches = 0x10,
    Hooks = 0x20,
    LightTraces = 0x40,
    HeavyTraces = 0x80
} LogComponents;

/// <summary>
/// The current log level.
/// </summary>
static LogComponents EnabledLogLevels = (LogComponents)(LightTraces);

/// <summary>
/// Logs a message to the Windows event log.
/// </summary>
/// <param name="type">EventLog type</param>
/// <param name="logLevel">Log level</param>
/// <param name="format">Format string</param>
static BOOL Log(WORD type, LogComponents logLevel, const wchar_t* format, ...)
{
    // The result
    BOOL result = FALSE;

    // We want to see this log
    if ((EnabledLogLevels & logLevel) != 0)
    {
        // Specify the source name for the event log.
        LPCWSTR sourceName = L"Mile.Cirno";

        // Register the event source
        HANDLE eventSource = RegisterEventSourceW(NULL, sourceName);

        // We managed to register the event source
        if (eventSource != NULL)
        {
            // Determine how long the formatted message is in characters
            va_list args;
            va_start(args, format);
            int length = _vscwprintf(format, args) + 1;
            va_end(args);

            // Allocate a buffer for the formatted message
            wchar_t* logMessage = (wchar_t*)_malloca(length * sizeof(wchar_t));

            // Format the log message.
            va_start(args, format);
            vswprintf_s(logMessage, length, format, args);
            va_end(args);

            // Log the message to the Application event log.
            const wchar_t* messageStrings[1] = { logMessage };
            result = ReportEventW(eventSource, type, 0, 1, NULL, 1, 0, messageStrings, NULL);
        }
    }

    // Return the result
    return result;
}

/// <summary>
/// The mount point for the file system.
/// </summary>
std::string g_MountPoint;

/// <summary>
/// The access name for the file system.
/// </summary>
std::string g_AccessName;

/// <summary>
/// The options for the file system.
/// </summary>
DOKAN_OPTIONS g_Options = { 0 };

/// <summary>
/// The instance of the Cirno client.
/// </summary>
Mile::Cirno::Client* g_Instance = nullptr;

/// <summary>
/// The root directory file ID.
/// </summary>
std::uint32_t g_RootDirectoryFileId = MILE_CIRNO_NOFID;

/// <summary>
/// Represents the benchmark data for an operation.
/// </summary>
struct BenchmarkData
{
    /// <summary>
    /// The operation name.
    /// </summary>
    std::string operation;

    /// <summary>
    /// The durations of each run.
    /// </summary>
    std::vector<std::chrono::microseconds> durations;
};

/// <summary>
/// Global mutex to protect the benchmark data.
/// </summary>
std::mutex g_BenchmarkMutex;

/// <summary>
/// Global benchmark map to store the benchmark data for each operation.
/// </summary>
std::map<std::string, BenchmarkData> g_BenchmarkMap;

/// <summary>
/// The last time a benchmark was logged.
/// </summary>
std::atomic<std::chrono::steady_clock::time_point> g_LastLogTime = std::chrono::steady_clock::now();

/// <summary>
/// Logs the benchmark data collected so far.
/// </summary>
void LogBenchmarkData()
{
    // Get the current time
    auto now = std::chrono::steady_clock::now();

    // At least one minute has passed since the last log
    if (now - g_LastLogTime.load() >= std::chrono::minutes(1))
    {
        // Prevent logging too frequently
        g_LastLogTime = now;

        // Produce a formatted string with the benchmark data
        std::string benchmark_data;
        for (auto& [op, data] : g_BenchmarkMap)
        {
            if (!data.durations.empty())
            {
                auto median = data.durations.size() % 2 == 0
                    ? (data.durations[data.durations.size() / 2 - 1] + data.durations[data.durations.size() / 2]) / 2
                    : data.durations[data.durations.size() / 2];

                benchmark_data += op + ": Median time = " + std::to_string(median.count()) + " microseconds\n";
            }
        }

        // There's at least one operation with recorded data
        if (!benchmark_data.empty())
        {
            // Log the benchmark data
            Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs Benchmark:\n%hs", g_MountPoint.c_str(), benchmark_data.c_str());

            // Clear the data after logging
            g_BenchmarkMap.clear();
        }
    }
}

/// <summary>
/// Records the benchmark data for a given operation.
/// </summary>
/// <param name="operation">The operation name.</param>
/// <param name="duration">The duration of the operation in microseconds.</param>
inline void RecordBenchmarkData(std::string const& operation, std::chrono::steady_clock::duration duration)
{
    // We want to log benchmark data
    if (EnabledLogLevels & DebugData)
    {
        // Lock the mutex to ensure thread-safe access
        std::lock_guard<std::mutex> lock(g_BenchmarkMutex);

        // Add the duration to the benchmark map
        g_BenchmarkMap[operation].operation = operation;
        g_BenchmarkMap[operation].durations.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration));

        // Log the benchmark data
        LogBenchmarkData();
    }
}

/// <summary>
/// Gets the process name for a given process ID.
/// </summary>
/// <param name="ProcessId">The process ID.</param>
/// <returns>The process name.</returns>
std::wstring GetProcessName(_In_ DWORD ProcessId)
{
    // The process name
    std::wstring ProcessName = L"Unknown";

    // No reason to get the process name if we won't log it (checking this makes sense as OpenProcess is expensive)
    if (EnabledLogLevels != Nothing)
    {
        // Open the process
        HANDLE ProcessHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);

        // We managed to open the process
        if (ProcessHandle)
        {
            // The process name buffer
            WCHAR Buffer[1024] = { 0 };

            // Get the process name
            if (GetModuleFileNameExW(ProcessHandle, NULL, Buffer, ARRAYSIZE(Buffer)))
            {
                // Convert the process name to a wide string
                ProcessName = Buffer;
            }

            // Close the process handle
            CloseHandle(ProcessHandle);
        }
    }

    // Return the process name
    return ProcessName;
}

/// <summary>
/// Generates a FNV-1a checksum for a given string.
/// </summary>
/// <param name="input">The input string.</param>
/// <returns>The FNV-1a checksum.</returns>
DWORD GenerateFNV1AChecksum(const std::string& input)
{
    // Offset basis for FNV-1a
    DWORD checksum = 0x811C9DC5;

    // Iterate the characters in the input string
    for (char c : input)
    {
        // XOR the byte
        checksum ^= static_cast<uint8_t>(c);

        // Multiply by the FNV prime
        checksum *= 0x01000193;
    }

    // Return the checksum
    return checksum;
}

/// <summary>
/// Gets the desired access string.
/// </summary>
/// <param name="DesiredAccess">The desired access.</param>
/// <returns>The desired access string.</returns>
std::wstring GetDesiredAccessString(_In_ ACCESS_MASK DesiredAccess)
{
    // The desired access
    std::wstring DesiredAccessString = L"";

    // The FILE_READ_DATA flag is set
    if (DesiredAccess & FILE_READ_DATA)
    {
        // Add the FILE_READ_DATA flag
        DesiredAccessString += L"FILE_READ_DATA";
    }

    // The FILE_READ_ATTRIBUTES flag is set
    if (DesiredAccess & FILE_READ_ATTRIBUTES)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_READ_ATTRIBUTES flag
        DesiredAccessString += L"FILE_READ_ATTRIBUTES";
    }

    // The FILE_READ_EA flag is set
    if (DesiredAccess & FILE_READ_EA)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_READ_EA flag
        DesiredAccessString += L"FILE_READ_EA";
    }

    // The FILE_WRITE_DATA flag is set
    if (DesiredAccess & FILE_WRITE_DATA)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_WRITE_DATA flag
        DesiredAccessString += L"FILE_WRITE_DATA";
    }

    // The FILE_WRITE_ATTRIBUTES flag is set
    if (DesiredAccess & FILE_WRITE_ATTRIBUTES)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_WRITE_ATTRIBUTES flag
        DesiredAccessString += L"FILE_WRITE_ATTRIBUTES";
    }

    // The FILE_WRITE_EA flag is set
    if (DesiredAccess & FILE_WRITE_EA)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_WRITE_EA flag
        DesiredAccessString += L"FILE_WRITE_EA";
    }

    // The FILE_APPEND_DATA flag is set
    if (DesiredAccess & FILE_APPEND_DATA)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_APPEND_DATA flag
        DesiredAccessString += L"FILE_APPEND_DATA";
    }

    // The FILE_EXECUTE flag is set
    if (DesiredAccess & FILE_EXECUTE)
    {
        // A spacer is required
        if (!DesiredAccessString.empty())
        {
            // Add a spacer
            DesiredAccessString += L" | ";
        }

        // Add the FILE_EXECUTE flag
        DesiredAccessString += L"FILE_EXECUTE";
    }

    // Return the desired access
    return DesiredAccessString;
}

/// <summary>
/// Gets the file attributes string.
/// </summary>
/// <param name="FileAttributes">The file attributes.</param>
/// <returns>The file attributes string.</returns>
std::wstring GetFileAttributesString(_In_ ULONG FileAttributes)
{
    // The file attributes
    std::wstring FileAttributesString = L"";

    // The FILE_ATTRIBUTE_READONLY flag is set
    if (FileAttributes & FILE_ATTRIBUTE_READONLY)
    {
        // Add the FILE_ATTRIBUTE_READONLY flag
        FileAttributesString += L"FILE_ATTRIBUTE_READONLY";
    }

    // The FILE_ATTRIBUTE_HIDDEN flag is set
    if (FileAttributes & FILE_ATTRIBUTE_HIDDEN)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }
        // Add the FILE_ATTRIBUTE_HIDDEN flag
        FileAttributesString += L"FILE_ATTRIBUTE_HIDDEN";
    }

    // The FILE_ATTRIBUTE_SYSTEM flag is set
    if (FileAttributes & FILE_ATTRIBUTE_SYSTEM)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }
        // Add the FILE_ATTRIBUTE_SYSTEM flag
        FileAttributesString += L"FILE_ATTRIBUTE_SYSTEM";
    }

    // The FILE_ATTRIBUTE_DIRECTORY flag is set
    if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_DIRECTORY flag
        FileAttributesString += L"FILE_ATTRIBUTE_DIRECTORY";
    }

    // The FILE_ATTRIBUTE_ARCHIVE flag is set
    if (FileAttributes & FILE_ATTRIBUTE_ARCHIVE)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_ARCHIVE flag
        FileAttributesString += L"FILE_ATTRIBUTE_ARCHIVE";
    }

    // The FILE_ATTRIBUTE_DEVICE flag is set
    if (FileAttributes & FILE_ATTRIBUTE_DEVICE)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_DEVICE flag
        FileAttributesString += L"FILE_ATTRIBUTE_DEVICE";
    }

    // The FILE_ATTRIBUTE_NORMAL flag is set
    if (FileAttributes & FILE_ATTRIBUTE_NORMAL)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_NORMAL flag
        FileAttributesString += L"FILE_ATTRIBUTE_NORMAL";
    }

    // The FILE_ATTRIBUTE_TEMPORARY flag is set
    if (FileAttributes & FILE_ATTRIBUTE_TEMPORARY)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_TEMPORARY flag
        FileAttributesString += L"FILE_ATTRIBUTE_TEMPORARY";
    }

    // The FILE_ATTRIBUTE_SPARSE_FILE flag is set
    if (FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_SPARSE_FILE flag
        FileAttributesString += L"FILE_ATTRIBUTE_SPARSE_FILE";
    }

    // The FILE_ATTRIBUTE_REPARSE_POINT flag is set
    if (FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_REPARSE_POINT flag
        FileAttributesString += L"FILE_ATTRIBUTE_REPARSE_POINT";
    }

    // The FILE_ATTRIBUTE_COMPRESSED flag is set
    if (FileAttributes & FILE_ATTRIBUTE_COMPRESSED)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_COMPRESSED flag
        FileAttributesString += L"FILE_ATTRIBUTE_COMPRESSED";
    }

    // The FILE_ATTRIBUTE_OFFLINE flag is set
    if (FileAttributes & FILE_ATTRIBUTE_OFFLINE)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_OFFLINE flag
        FileAttributesString += L"FILE_ATTRIBUTE_OFFLINE";
    }

    // The FILE_ATTRIBUTE_NOT_CONTENT_INDEXED flag is set
    if (FileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED flag
        FileAttributesString += L"FILE_ATTRIBUTE_NOT_CONTENT_INDEXED";
    }

    // The FILE_ATTRIBUTE_ENCRYPTED flag is set
    if (FileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_ENCRYPTED flag
        FileAttributesString += L"FILE_ATTRIBUTE_ENCRYPTED";
    }

    // The FILE_ATTRIBUTE_INTEGRITY_STREAM flag is set
    if (FileAttributes & FILE_ATTRIBUTE_INTEGRITY_STREAM)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_INTEGRITY_STREAM flag
        FileAttributesString += L"FILE_ATTRIBUTE_INTEGRITY_STREAM";
    }

    // The FILE_ATTRIBUTE_VIRTUAL flag is set
    if (FileAttributes & FILE_ATTRIBUTE_VIRTUAL)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_VIRTUAL flag
        FileAttributesString += L"FILE_ATTRIBUTE_VIRTUAL";
    }

    // The FILE_ATTRIBUTE_NO_SCRUB_DATA flag is set
    if (FileAttributes & FILE_ATTRIBUTE_NO_SCRUB_DATA)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_NO_SCRUB_DATA flag
        FileAttributesString += L"FILE_ATTRIBUTE_NO_SCRUB_DATA";
    }

    // The FILE_ATTRIBUTE_EA flag is set
    if (FileAttributes & FILE_ATTRIBUTE_EA)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_EA flag
        FileAttributesString += L"FILE_ATTRIBUTE_EA";
    }

    // The FILE_ATTRIBUTE_PINNED flag is set
    if (FileAttributes & FILE_ATTRIBUTE_PINNED)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_PINNED flag
        FileAttributesString += L"FILE_ATTRIBUTE_PINNED";
    }

    // The FILE_ATTRIBUTE_UNPINNED flag is set
    if (FileAttributes & FILE_ATTRIBUTE_UNPINNED)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_UNPINNED flag
        FileAttributesString += L"FILE_ATTRIBUTE_UNPINNED";
    }

    // The FILE_ATTRIBUTE_RECALL_ON_OPEN flag is set
    if (FileAttributes & FILE_ATTRIBUTE_RECALL_ON_OPEN)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_RECALL_ON_OPEN flag
        FileAttributesString += L"FILE_ATTRIBUTE_RECALL_ON_OPEN";
    }

    // The FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS flag is set
    if (FileAttributes & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
    {
        // A spacer is required
        if (!FileAttributesString.empty())
        {
            // Add a spacer
            FileAttributesString += L" | ";
        }

        // Add the FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS flag
        FileAttributesString += L"FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS";
    }

    // Return the file attributes
    return FileAttributesString;
}

/// <summary>
/// Gets the create disposition string.
/// </summary>
/// <param name="CreateDisposition">The create disposition.</param>
/// <returns>The create disposition string.</returns>
std::wstring GetCreateDispositionString(_In_ ULONG CreateDisposition)
{
    // The create disposition
    std::wstring CreateDispositionString = L"UNKNOWN";

    // Get the create disposition
    switch (CreateDisposition)
    {
    case FILE_OPEN:
        CreateDispositionString = L"FILE_OPEN";
        break;
    case FILE_CREATE:
        CreateDispositionString = L"FILE_CREATE";
        break;
    case FILE_OPEN_IF:
        CreateDispositionString = L"FILE_OPEN_IF";
        break;
    case FILE_OVERWRITE:
        CreateDispositionString = L"FILE_OVERWRITE";
        break;
    case FILE_OVERWRITE_IF:
        CreateDispositionString = L"FILE_OVERWRITE_IF";
        break;
    case FILE_SUPERSEDE:
        CreateDispositionString = L"FILE_SUPERSEDE";
        break;
    default:
        break;
    }

    // Return the create disposition
    return CreateDispositionString;
}

/// <summary>
/// Gets the create options string.
/// </summary>
/// <param name="CreateOptions">The create options.</param>
/// <returns>The create options string.</returns>
std::wstring GetCreateOptionsString(_In_ ULONG CreateOptions)
{
    // The create options
    std::wstring CreateOptionsString = L"";

    // The FILE_DIRECTORY_FILE flag is set
    if (CreateOptions & FILE_DIRECTORY_FILE)
    {
        // Add the FILE_DIRECTORY_FILE flag
        CreateOptionsString += L"FILE_DIRECTORY_FILE";
    }

    // The FILE_WRITE_THROUGH flag is set
    if (CreateOptions & FILE_WRITE_THROUGH)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_WRITE_THROUGH flag
        CreateOptionsString += L"FILE_WRITE_THROUGH";
    }

    // The FILE_SEQUENTIAL_ONLY flag is set
    if (CreateOptions & FILE_SEQUENTIAL_ONLY)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_SEQUENTIAL_ONLY flag
        CreateOptionsString += L"FILE_SEQUENTIAL_ONLY";
    }

    // The FILE_NO_INTERMEDIATE_BUFFERING flag is set
    if (CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_NO_INTERMEDIATE_BUFFERING flag
        CreateOptionsString += L"FILE_NO_INTERMEDIATE_BUFFERING";
    }

    // The FILE_SYNCHRONOUS_IO_ALERT flag is set
    if (CreateOptions & FILE_SYNCHRONOUS_IO_ALERT)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_SYNCHRONOUS_IO_ALERT flag
        CreateOptionsString += L"FILE_SYNCHRONOUS_IO_ALERT";
    }

    // The FILE_SYNCHRONOUS_IO_NONALERT flag is set
    if (CreateOptions & FILE_SYNCHRONOUS_IO_NONALERT)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_SYNCHRONOUS_IO_NONALERT flag
        CreateOptionsString += L"FILE_SYNCHRONOUS_IO_NONALERT";
    }

    // The FILE_NON_DIRECTORY_FILE flag is set
    if (CreateOptions & FILE_NON_DIRECTORY_FILE)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_NON_DIRECTORY_FILE flag
        CreateOptionsString += L"FILE_NON_DIRECTORY_FILE";
    }

    // The FILE_CREATE_TREE_CONNECTION flag is set
    if (CreateOptions & FILE_CREATE_TREE_CONNECTION)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_CREATE_TREE_CONNECTION flag
        CreateOptionsString += L"FILE_CREATE_TREE_CONNECTION";
    }

    // The FILE_COMPLETE_IF_OPLOCKED flag is set
    if (CreateOptions & FILE_COMPLETE_IF_OPLOCKED)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_COMPLETE_IF_OPLOCKED flag
        CreateOptionsString += L"FILE_COMPLETE_IF_OPLOCKED";
    }

    // The FILE_NO_EA_KNOWLEDGE flag is set
    if (CreateOptions & FILE_NO_EA_KNOWLEDGE)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_NO_EA_KNOWLEDGE flag
        CreateOptionsString += L"FILE_NO_EA_KNOWLEDGE";
    }

    // The FILE_OPEN_REMOTE_INSTANCE flag is set
    if (CreateOptions & FILE_OPEN_REMOTE_INSTANCE)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_REMOTE_INSTANCE flag
        CreateOptionsString += L"FILE_OPEN_REMOTE_INSTANCE";
    }

    // The FILE_RANDOM_ACCESS flag is set
    if (CreateOptions & FILE_RANDOM_ACCESS)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_RANDOM_ACCESS flag
        CreateOptionsString += L"FILE_RANDOM_ACCESS";
    }

    // The FILE_DELETE_ON_CLOSE flag is set
    if (CreateOptions & FILE_DELETE_ON_CLOSE)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_DELETE_ON_CLOSE flag
        CreateOptionsString += L"FILE_DELETE_ON_CLOSE";
    }

    // The FILE_OPEN_BY_FILE_ID flag is set
    if (CreateOptions & FILE_OPEN_BY_FILE_ID)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_BY_FILE_ID flag
        CreateOptionsString += L"FILE_OPEN_BY_FILE_ID";
    }

    // The FILE_OPEN_FOR_BACKUP_INTENT flag is set
    if (CreateOptions & FILE_OPEN_FOR_BACKUP_INTENT)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_FOR_BACKUP_INTENT flag
        CreateOptionsString += L"FILE_OPEN_FOR_BACKUP_INTENT";
    }

    // The FILE_NO_COMPRESSION flag is set
    if (CreateOptions & FILE_NO_COMPRESSION)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_NO_COMPRESSION flag
        CreateOptionsString += L"FILE_NO_COMPRESSION";
    }

    // The FILE_OPEN_REQUIRING_OPLOCK flag is set
    if (CreateOptions & FILE_OPEN_REQUIRING_OPLOCK)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_REQUIRING_OPLOCK flag
        CreateOptionsString += L"FILE_OPEN_REQUIRING_OPLOCK";
    }

    // The FILE_DISALLOW_EXCLUSIVE flag is set
    if (CreateOptions & FILE_DISALLOW_EXCLUSIVE)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_DISALLOW_EXCLUSIVE flag
        CreateOptionsString += L"FILE_DISALLOW_EXCLUSIVE";
    }

    // The FILE_SESSION_AWARE flag is set
    if (CreateOptions & FILE_SESSION_AWARE)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_SESSION_AWARE flag
        CreateOptionsString += L"FILE_SESSION_AWARE";
    }

    // The FILE_RESERVE_OPFILTER flag is set
    if (CreateOptions & FILE_RESERVE_OPFILTER)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_RESERVE_OPFILTER flag
        CreateOptionsString += L"FILE_RESERVE_OPFILTER";
    }

    // The FILE_OPEN_REPARSE_POINT flag is set
    if (CreateOptions & FILE_OPEN_REPARSE_POINT)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_REPARSE_POINT flag
        CreateOptionsString += L"FILE_OPEN_REPARSE_POINT";
    }

    // The FILE_OPEN_NO_RECALL flag is set
    if (CreateOptions & FILE_OPEN_NO_RECALL)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_NO_RECALL flag
        CreateOptionsString += L"FILE_OPEN_NO_RECALL";
    }

    // The FILE_OPEN_FOR_FREE_SPACE_QUERY flag is set
    if (CreateOptions & FILE_OPEN_FOR_FREE_SPACE_QUERY)
    {
        // A spacer is required
        if (!CreateOptionsString.empty())
        {
            // Add a spacer
            CreateOptionsString += L" | ";
        }

        // Add the FILE_OPEN_FOR_FREE_SPACE_QUERY flag
        CreateOptionsString += L"FILE_OPEN_FOR_FREE_SPACE_QUERY";
    }

    // Return the create options
    return CreateOptionsString;
}

/// <summary>
/// Gets the create options string.
/// </summary>
/// <param name="CreateOptions">The create options.</param>
/// <returns>The create options string.</returns>
std::wstring GetSecurityInformationString(_In_ SECURITY_INFORMATION securityInformation)
{
    // The security information
    std::wstring SecurityInformationString = L"";

    // The OWNER_SECURITY_INFORMATION flag is set
    if (securityInformation & OWNER_SECURITY_INFORMATION)
    {
        // Add the OWNER_SECURITY_INFORMATION flag
        SecurityInformationString += L"OWNER_SECURITY_INFORMATION";
    }

    // The GROUP_SECURITY_INFORMATION flag is set
    if (securityInformation & GROUP_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the GROUP_SECURITY_INFORMATION flag
        SecurityInformationString += L"GROUP_SECURITY_INFORMATION";
    }

    // The DACL_SECURITY_INFORMATION flag is set
    if (securityInformation & DACL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the DACL_SECURITY_INFORMATION flag
        SecurityInformationString += L"DACL_SECURITY_INFORMATION";
    }

    // The SACL_SECURITY_INFORMATION flag is set
    if (securityInformation & SACL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the SACL_SECURITY_INFORMATION flag
        SecurityInformationString += L"SACL_SECURITY_INFORMATION";
    }

    // The LABEL_SECURITY_INFORMATION flag is set
    if (securityInformation & LABEL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the LABEL_SECURITY_INFORMATION flag
        SecurityInformationString += L"LABEL_SECURITY_INFORMATION";
    }

    // The ATTRIBUTE_SECURITY_INFORMATION flag is set
    if (securityInformation & ATTRIBUTE_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the ATTRIBUTE_SECURITY_INFORMATION flag
        SecurityInformationString += L"ATTRIBUTE_SECURITY_INFORMATION";
    }

    // The SCOPE_SECURITY_INFORMATION flag is set
    if (securityInformation & SCOPE_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the SCOPE_SECURITY_INFORMATION flag
        SecurityInformationString += L"SCOPE_SECURITY_INFORMATION";
    }

    // The PROCESS_TRUST_LABEL_SECURITY_INFORMATION flag is set
    if (securityInformation & PROCESS_TRUST_LABEL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the PROCESS_TRUST_LABEL_SECURITY_INFORMATION flag
        SecurityInformationString += L"PROCESS_TRUST_LABEL_SECURITY_INFORMATION";
    }

    // The ACCESS_FILTER_SECURITY_INFORMATION flag is set
    if (securityInformation & ACCESS_FILTER_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the ACCESS_FILTER_SECURITY_INFORMATION flag
        SecurityInformationString += L"ACCESS_FILTER_SECURITY_INFORMATION";
    }

    // The BACKUP_SECURITY_INFORMATION flag is set
    if (securityInformation & BACKUP_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the BACKUP_SECURITY_INFORMATION flag
        SecurityInformationString += L"BACKUP_SECURITY_INFORMATION";
    }

    // The UNPROTECTED_SACL_SECURITY_INFORMATION flag is set
    if (securityInformation & UNPROTECTED_SACL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the UNPROTECTED_SACL_SECURITY_INFORMATION flag
        SecurityInformationString += L"UNPROTECTED_SACL_SECURITY_INFORMATION";
    }

    // The UNPROTECTED_DACL_SECURITY_INFORMATION flag is set
    if (securityInformation & UNPROTECTED_DACL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the UNPROTECTED_DACL_SECURITY_INFORMATION flag
        SecurityInformationString += L"UNPROTECTED_DACL_SECURITY_INFORMATION";
    }

    // The PROTECTED_SACL_SECURITY_INFORMATION flag is set
    if (securityInformation & PROTECTED_SACL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the PROTECTED_SACL_SECURITY_INFORMATION flag
        SecurityInformationString += L"PROTECTED_SACL_SECURITY_INFORMATION";
    }

    // The PROTECTED_DACL_SECURITY_INFORMATION flag is set
    if (securityInformation & PROTECTED_DACL_SECURITY_INFORMATION)
    {
        // A spacer is required
        if (!SecurityInformationString.empty())
        {
            // Add a spacer
            SecurityInformationString += L" | ";
        }

        // Add the PROTECTED_DACL_SECURITY_INFORMATION flag
        SecurityInformationString += L"PROTECTED_DACL_SECURITY_INFORMATION";
    }

    // Return the security information
    return SecurityInformationString;
}

// Win32 time epoch is 00:00:00, January 1 1601.
// UNIX time epoch is 00:00:00, January 1 1970.
// There are 11644473600 seconds between these two epochs.
const std::uint64_t SecondsBetweenWin32TimeAndUnixTime = 11644473600ULL;

inline FILETIME ToFileTime(
    std::uint64_t UnixTimeSeconds,
    std::uint64_t UnixTimeNanoseconds)
{
    constexpr std::uint64_t HUNDRED_NS_PER_SEC = 10'000'000ULL;
    constexpr std::uint64_t UNIX_TO_WIN_EPOCH_SECS = 11644473600ULL;

    std::uint64_t total100ns =
        (UnixTimeSeconds + UNIX_TO_WIN_EPOCH_SECS) * HUNDRED_NS_PER_SEC +
        (UnixTimeNanoseconds / 100);

    FILETIME ft;
    ft.dwLowDateTime = static_cast<DWORD>(total100ns);
    ft.dwHighDateTime = static_cast<DWORD>(total100ns >> 32);
    return ft;
}

NTSTATUS DOKAN_CALLBACK MileCirnoZwCreateFile(
    _In_ LPCWSTR FileName,
    _In_ PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    // The unreferenced parameters
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(FileAttributes);
    UNREFERENCED_PARAMETER(ShareAccess);

    // Start measuring time
    auto start_time = std::chrono::steady_clock::now();

    // The result
    NTSTATUS result = STATUS_OBJECT_NAME_NOT_FOUND;

    // Return a invalid file ID by default
    DokanFileInfo->Context = MILE_CIRNO_NOFID;

    // Ignore the system volume information and recycle bin
    if (_wcsicmp(FileName, LR"(\System Volume Information)") != 0 &&
        _wcsicmp(FileName, LR"(\$RECYCLE.BIN)") != 0)
    {
        // Build a relative path
        std::filesystem::path RelativePath(&FileName[1]);

        // The flags for the open/create request
        std::uint32_t Flags = MileCirnoLinuxOpenCreateFlagLargeFile | MileCirnoLinuxOpenCreateFlagCloseOnExecute;

        // We need write access
        if (CreateDisposition != FILE_OPEN || DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES))
        {
            // Set the read/write flag
            Flags |= MileCirnoLinuxOpenCreateFlagReadWrite;
        }

        // We want asynchronous I/O
        if (!(CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)))
        {
            // Set the non-block flag
            Flags |= MileCirnoLinuxOpenCreateFlagNonBlock;
        }

        // We want to create the file if it doesn't exist
        if (CreateDisposition != FILE_OPEN)
        {
            // Set the create flag
            Flags |= MileCirnoLinuxOpenCreateFlagCreate;
        }

        // We want to create the file only if it doesn't exist
        if (CreateDisposition == FILE_CREATE)
        {
            // Set the create-only-when-not-exist flag
            Flags |= MileCirnoLinuxOpenCreateFlagCreateOnlyWhenNotExist;
        }

        // We're trying to truncate an existing file
        if (CreateDisposition == FILE_SUPERSEDE ||
            CreateDisposition == FILE_OVERWRITE ||
            CreateDisposition == FILE_OVERWRITE_IF)
        {
            // Set the truncate flag
            Flags |= MileCirnoLinuxOpenCreateFlagTruncate;
        }

        // Build a walk request to the requested file
        Mile::Cirno::WalkRequest WalkRequest;
        WalkRequest.FileId = g_RootDirectoryFileId;
        WalkRequest.NewFileId = g_Instance->AllocateFileId();
        for (std::filesystem::path const& Element : RelativePath)
        {
            // Push the path node into the back of the walk request
            WalkRequest.Names.push_back(Element.string());
        }

        try
        {
            // The caller wants to open the root directory
            if (_wcsicmp(FileName, LR"(\)") == 0)
            {
                // Build a attach request to the root directory
                Mile::Cirno::AttachRequest AttachRequest;
                AttachRequest.FileId = WalkRequest.NewFileId;
                AttachRequest.AuthenticationFileId = MILE_CIRNO_NOFID;
                AttachRequest.UserName = "";
                AttachRequest.AccessName = g_AccessName;
                AttachRequest.NumericUserName = MILE_CIRNO_NONUNAME;
                g_Instance->Attach(AttachRequest);
            }

            // The caller wants to open something else
            else
            {
                // Execute the walk request, which creates a local file ID for the requested file
                g_Instance->Walk(WalkRequest);
            }

            // Get the file's attributes
            Mile::Cirno::GetAttrRequest GetAttrRequest;
            GetAttrRequest.FileId = WalkRequest.NewFileId;
            GetAttrRequest.RequestMask = MileCirnoLinuxGetAttrFlagMode;
            Mile::Cirno::GetAttrResponse GetAttrResponse = g_Instance->GetAttr(GetAttrRequest);

            // We're handling a directory
            if (S_IFDIR & GetAttrResponse.Mode)
            {
                // Set the directory flag
                Flags |= MileCirnoLinuxOpenCreateFlagDirectory;

                // Let the caller know the handle belongs to a directory
                DokanFileInfo->IsDirectory = TRUE;
            }

            // Execute a file open request
            Mile::Cirno::LinuxOpenRequest Request;
            Request.FileId = WalkRequest.NewFileId;
            Request.Flags = _wcsicmp(FileName, LR"(\)") == 0 ? MileCirnoLinuxOpenCreateFlagReadOnly : Flags;
            g_Instance->LinuxOpen(Request);

            // Return the file ID to the caller
            DokanFileInfo->Context = WalkRequest.NewFileId;

            // Let the caller know that we opened an existing file
            result = STATUS_SUCCESS;
        }
        catch (...)
        {
            // We have a file ID that needs to get clunked
            if (MILE_CIRNO_NOFID != WalkRequest.NewFileId)
            {
                try
                {
                    // Clunk the file ID
                    Mile::Cirno::ClunkRequest ClunkRequest;
                    ClunkRequest.FileId = WalkRequest.NewFileId;
                    g_Instance->Clunk(ClunkRequest);
                }
                catch (...) { }

                // Free the file ID
                g_Instance->FreeFileId(WalkRequest.NewFileId);
            }

            // The file or directory doesn't exist, but the creation disposition allows for a create file fallback
            if (CreateDisposition == FILE_SUPERSEDE ||
                CreateDisposition == FILE_CREATE ||
                CreateDisposition == FILE_OPEN_IF ||
                CreateDisposition == FILE_OVERWRITE_IF)
            {
                // Build a walk request to the requested file's parent directory
                WalkRequest.FileId = g_RootDirectoryFileId;
                WalkRequest.NewFileId = g_Instance->AllocateFileId();
                WalkRequest.Names.clear();
                for (std::filesystem::path const& Element : RelativePath.parent_path())
                {
                    // Push the path node into the back of the walk request
                    WalkRequest.Names.push_back(Element.string());
                }

                try
                {
                    // Execute the walk request, which creates a local file ID for the requested file's parent directory
                    g_Instance->Walk(WalkRequest);

                    // Get the file's parent directory's attributes (which we'll pull the group ID from)
                    Mile::Cirno::GetAttrRequest GetAttrRequest;
                    GetAttrRequest.FileId = WalkRequest.NewFileId;
                    GetAttrRequest.RequestMask = MileCirnoLinuxGetAttrFlagMode;
                    Mile::Cirno::GetAttrResponse GetAttrResponse = g_Instance->GetAttr(GetAttrRequest);

                    // We're trying to create a directory
                    if (CreateOptions & FILE_DIRECTORY_FILE)
                    {
                        // Set the directory flag
                        Flags |= MileCirnoLinuxOpenCreateFlagDirectory;

                        // Let the caller know the handle belongs to a directory
                        DokanFileInfo->IsDirectory = TRUE;

                        // Execute a directory creation request
                        Mile::Cirno::MkDirRequest Request;
                        Request.DirectoryFileId = WalkRequest.NewFileId;
                        Request.Name = RelativePath.filename().string();
                        Request.Mode = 0777;
                        Request.Gid = GetAttrResponse.GroupId;
                        g_Instance->MkDir(Request);
                    }

                    // We're trying to create a file
                    else
                    {
                        // Execute a file creation request
                        Mile::Cirno::LinuxCreateRequest Request;
                        Request.FileId = WalkRequest.NewFileId;
                        Request.Name = RelativePath.filename().string();
                        Request.Flags = Flags;
                        Request.Mode = 0777;
                        Request.Gid = GetAttrResponse.GroupId;
                        g_Instance->LinuxCreate(Request);
                    }

                    // Return the file ID to the caller
                    DokanFileInfo->Context = WalkRequest.NewFileId;

                    // Let the caller know that we created a new file
                    result = STATUS_SUCCESS;
                }
                catch (...)
                {
                    // We have a file ID that needs to get clunked
                    if (MILE_CIRNO_NOFID != WalkRequest.NewFileId)
                    {
                        try
                        {
                            // Clunk the file ID
                            Mile::Cirno::ClunkRequest ClunkRequest;
                            ClunkRequest.FileId = WalkRequest.NewFileId;
                            g_Instance->Clunk(ClunkRequest);
                        }
                        catch (...) { }

                        // Free the file ID
                        g_Instance->FreeFileId(WalkRequest.NewFileId);
                    }
                }
            }

            // The file doesn't exist and we don't want to create it
            else
            {
                // Build a walk request to the requested file's parent directory
                WalkRequest.FileId = g_RootDirectoryFileId;
                WalkRequest.NewFileId = g_Instance->AllocateFileId();
                WalkRequest.Names.clear();
                for (std::filesystem::path const& Element : RelativePath.parent_path())
                {
                    // Push the path node into the back of the walk request
                    WalkRequest.Names.push_back(Element.string());
                }

                try
                {
                    // Create a cleanup handler to free the parent directory's temporary file ID
                    auto CurrentCleanupHandler = Mile::ScopeExitTaskHandler([&]()
                        {
                            if (MILE_CIRNO_NOFID != WalkRequest.NewFileId)
                            {
                                try
                                {
                                    Mile::Cirno::ClunkRequest ClunkRequest;
                                    ClunkRequest.FileId = WalkRequest.NewFileId;
                                    g_Instance->Clunk(ClunkRequest);
                                }
                                catch (...) { }
                                g_Instance->FreeFileId(WalkRequest.NewFileId);
                            }
                        });

                    // Execute the walk request, which creates a local file ID for the requested file's parent directory
                    g_Instance->Walk(WalkRequest);
                }
                catch (...)
                {
                    // One of the parent directory's doesn't exist
                    result = STATUS_OBJECT_PATH_NOT_FOUND;
                }
            }
        }
    }

    // Record the benchmark data
    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    // Return the result
    return result;
}

void DOKAN_CALLBACK MileCirnoCleanup(
    _In_ LPCWSTR FileName,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    NTSTATUS result = MILE_CIRNO_NOFID != FileId ? STATUS_SUCCESS : STATUS_NOT_FOUND;

    if (result == STATUS_SUCCESS && DokanFileInfo->DeletePending)
    {
        try
        {
            Mile::Cirno::RemoveRequest Request;
            Request.FileId = FileId;
            g_Instance->Remove(Request);
        }
        catch (...) { }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);
}

void DOKAN_CALLBACK MileCirnoCloseFile(
    _In_ LPCWSTR FileName,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    NTSTATUS result = MILE_CIRNO_NOFID != FileId ? STATUS_SUCCESS : STATUS_NOT_FOUND;

    if (result == STATUS_SUCCESS)
    {
        try
        {
            Mile::Cirno::ClunkRequest Request;
            Request.FileId = FileId;
            g_Instance->Clunk(Request);
        }
        catch (...) { }

        g_Instance->FreeFileId(FileId);
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);
}

NTSTATUS DOKAN_CALLBACK MileCirnoReadFile(
    _In_ LPCWSTR FileName,
    _Out_opt_ LPVOID Buffer,
    _In_ DWORD BufferLength,
    _Out_opt_ LPDWORD ReadLength,
    _In_ LONGLONG Offset,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    NTSTATUS result = STATUS_NOT_IMPLEMENTED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    if (ReadLength)
    {
        *ReadLength = 0;
    }

    if (MILE_CIRNO_NOFID != FileId)
    {
        DWORD ProceededSize = 0;
        DWORD UnproceededSize = BufferLength;

        try
        {
            while (UnproceededSize)
            {
                Mile::Cirno::ReadRequest Request;
                Request.FileId = FileId;
                Request.Offset = Offset + ProceededSize;
                Request.Count = Mile::Cirno::DefaultMaximumMessageSize;
                Request.Count -= Mile::Cirno::ReadResponseHeaderSize;
                if (UnproceededSize < Request.Count)
                {
                    Request.Count = UnproceededSize;
                }
                Mile::Cirno::ReadResponse Response = g_Instance->Read(Request);
                DWORD CurrentProceededSize =
                    static_cast<DWORD>(Response.Data.size());
                if (!CurrentProceededSize)
                {
                    break;
                }
                if (Buffer)
                {
                    std::memcpy(
                        static_cast<std::uint8_t*>(Buffer) + ProceededSize,
                        &Response.Data[0],
                        CurrentProceededSize);
                }
                ProceededSize += CurrentProceededSize;
                UnproceededSize -= CurrentProceededSize;
            }

            result = STATUS_SUCCESS;
        }
        catch (...) { }

        if (ReadLength)
        {
            *ReadLength = ProceededSize;
        }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoWriteFile(
    _In_ LPCWSTR FileName,
    _In_ LPCVOID Buffer,
    _In_ DWORD NumberOfBytesToWrite,
    _Out_opt_ LPDWORD NumberOfBytesWritten,
    _In_ LONGLONG Offset,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    NTSTATUS result = STATUS_NOT_IMPLEMENTED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    if (MILE_CIRNO_NOFID != FileId)
    {
        if (DokanFileInfo->WriteToEndOfFile || Offset == -1)
        {
            try
            {
                Mile::Cirno::GetAttrRequest Request;
                Request.FileId = FileId;
                Request.RequestMask = MileCirnoLinuxGetAttrFlagSize;
                Mile::Cirno::GetAttrResponse Response = g_Instance->GetAttr(Request);
                Offset = Response.FileSize;
            }
            catch (...) { }
        }

        DWORD MaximumChunkSize = Mile::Cirno::DefaultMaximumMessageSize - Mile::Cirno::WriteRequestHeaderSize;

        DWORD ProceededSize = 0;
        DWORD UnproceededSize = NumberOfBytesToWrite;

        try
        {
            while (UnproceededSize)
            {
                DWORD chunkSize = NumberOfBytesToWrite - ProceededSize;

                if (chunkSize > MaximumChunkSize)
                {
                    chunkSize = MaximumChunkSize;
                }

                Mile::Cirno::WriteRequest Request;
                Request.FileId = FileId;
                Request.Offset = Offset + ProceededSize;
                const std::uint8_t* chunk = static_cast<const std::uint8_t*>(Buffer) + ProceededSize;
                Request.Data = std::vector<std::uint8_t>(chunk, chunk + chunkSize);
                Mile::Cirno::WriteResponse Response = g_Instance->Write(Request);
                DWORD CurrentProceededSize = static_cast<DWORD>(Response.Count);
                if (!CurrentProceededSize)
                {
                    break;
                }
                ProceededSize += CurrentProceededSize;
                UnproceededSize -= CurrentProceededSize;
            }

            result = STATUS_SUCCESS;
        }
        catch (...) { }

        if (NumberOfBytesWritten)
        {
            *NumberOfBytesWritten = ProceededSize;
        }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoFlushFileBuffers(
    _In_ LPCWSTR FileName,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoGetFileInformation(
    _In_ LPCWSTR FileName,
    _Out_ LPBY_HANDLE_FILE_INFORMATION Buffer,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    NTSTATUS result = STATUS_NOT_IMPLEMENTED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    if (MILE_CIRNO_NOFID != FileId)
    {
        std::memset(Buffer, 0, sizeof(BY_HANDLE_FILE_INFORMATION));

        try
        {
            Mile::Cirno::GetAttrRequest Request;
            Request.FileId = FileId;
            Request.RequestMask =
                MileCirnoLinuxGetAttrFlagMode |
                MileCirnoLinuxGetAttrFlagLastAccessTime |
                MileCirnoLinuxGetAttrFlagLastWriteTime |
                MileCirnoLinuxGetAttrFlagSize;
            Mile::Cirno::GetAttrResponse Response = g_Instance->GetAttr(Request);

            if (S_IFDIR & Response.Mode)
            {
                Buffer->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
            }
            else
            {
                Buffer->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
            }

            Buffer->ftLastAccessTime = ::ToFileTime(
                Response.LastAccessTimeSeconds,
                Response.LastAccessTimeNanoseconds);
            Buffer->ftLastWriteTime = ::ToFileTime(
                Response.LastWriteTimeSeconds,
                Response.LastWriteTimeNanoseconds);
            Buffer->ftCreationTime = Buffer->ftLastWriteTime;

            Buffer->dwVolumeSerialNumber = GenerateFNV1AChecksum(g_AccessName);

            Buffer->nFileSizeHigh =
                static_cast<DWORD>(Response.FileSize >> 32);
            Buffer->nFileSizeLow =
                static_cast<DWORD>(Response.FileSize);

            Buffer->nNumberOfLinks =
                static_cast<DWORD>(Response.NumberOfHardLinks);

            Buffer->nFileIndexHigh = static_cast<DWORD>(Response.UniqueId.Path >> 32);
            Buffer->nFileIndexLow = static_cast<DWORD>(Response.UniqueId.Path);

            result = STATUS_SUCCESS;
        }
        catch (...) { }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoFindFiles(
    _In_ LPCWSTR FileName,
    _In_ PFillFindData FillFindData,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();
    NTSTATUS result = STATUS_NOT_IMPLEMENTED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);
    if (FileId == MILE_CIRNO_NOFID || !DokanFileInfo->IsDirectory) {
        RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);
        return result;
    }

    try {
        std::uint64_t LastOffset = 0;
        std::wstring WideNameBuffer;

        FILETIME currentTime;
        ::GetSystemTimeAsFileTime(&currentTime);

        do {
            Mile::Cirno::ReadDirRequest Request;
            Request.FileId = FileId;
            Request.Offset = LastOffset;
            LastOffset = 0;
            Request.Count = Mile::Cirno::DefaultMaximumMessageSize - Mile::Cirno::ReadDirResponseHeaderSize;

            Mile::Cirno::ReadDirResponse Response = g_Instance->ReadDir(Request);

            for (const auto& Entry : Response.Data) {
                LastOffset = Entry.Offset;

                if (Entry.Name == "." || Entry.Name == "..")
                    continue;

                WIN32_FIND_DATAW FindData{};
                FindData.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;

                WideNameBuffer = Mile::ToWideString(CP_UTF8, Entry.Name);
                wcsncpy_s(FindData.cFileName, WideNameBuffer.c_str(), _TRUNCATE);

                bool isDirectory = (Entry.UniqueId.Type & 0x80) != 0;

                if (isDirectory) {
                    FindData.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;

                    FindData.ftCreationTime = currentTime;
                    FindData.ftLastAccessTime = currentTime;
                    FindData.ftLastWriteTime = currentTime;

                    FindData.nFileSizeHigh = 0;
                    FindData.nFileSizeLow = 0;
                }
                else {
                    try {
                        Mile::Cirno::WalkRequest WalkRequest;
                        WalkRequest.FileId = FileId;
                        WalkRequest.NewFileId = g_Instance->AllocateFileId();
                        WalkRequest.Names.emplace_back(Entry.Name);

                        g_Instance->Walk(WalkRequest);

                        auto CleanupHandler = Mile::ScopeExitTaskHandler([&]() {
                            if (WalkRequest.NewFileId != MILE_CIRNO_NOFID) {
                                try {
                                    Mile::Cirno::ClunkRequest ClunkReq{ WalkRequest.NewFileId };
                                    g_Instance->Clunk(ClunkReq);
                                }
                                catch (...) {}
                                g_Instance->FreeFileId(WalkRequest.NewFileId);
                            }
                            });

                        Mile::Cirno::GetAttrRequest InfoReq;
                        InfoReq.FileId = WalkRequest.NewFileId;
                        InfoReq.RequestMask =
                            MileCirnoLinuxGetAttrFlagSize;

                        auto InfoResp = g_Instance->GetAttr(InfoReq);

                        FindData.ftCreationTime = currentTime;
                        FindData.ftLastAccessTime = currentTime;
                        FindData.ftLastWriteTime = currentTime;

                        FindData.nFileSizeHigh = static_cast<DWORD>(InfoResp.FileSize >> 32);
                        FindData.nFileSizeLow = static_cast<DWORD>(InfoResp.FileSize);
                    }
                    catch (...) {
                        FindData.ftCreationTime = currentTime;
                        FindData.ftLastAccessTime = currentTime;
                        FindData.ftLastWriteTime = currentTime;

                        FindData.nFileSizeHigh = 0;
                        FindData.nFileSizeLow = 0;
                    }
                }

                FillFindData(&FindData, DokanFileInfo);
            }
        } while (LastOffset);

        result = STATUS_SUCCESS;
    }
    catch (...) { }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);
    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoSetFileAttributesW(
    _In_ LPCWSTR FileName,
    _In_ DWORD FileAttributes,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(FileAttributes);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoSetFileTime(
    _In_ LPCWSTR FileName,
    _In_ CONST FILETIME* CreationTime,
    _In_ CONST FILETIME* LastAccessTime,
    _In_ CONST FILETIME* LastWriteTime,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(CreationTime);
    UNREFERENCED_PARAMETER(LastAccessTime);
    UNREFERENCED_PARAMETER(LastWriteTime);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoDeleteFileW(
    _In_ LPCWSTR FileName,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoDeleteDirectory(
    _In_ LPCWSTR FileName,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    NTSTATUS result = STATUS_ACCESS_DENIED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    if (MILE_CIRNO_NOFID != FileId && DokanFileInfo->IsDirectory)
    {
        try
        {
            Mile::Cirno::ReadDirRequest Request;
            Request.FileId = FileId;
            Request.Offset = 0;
            Request.Count = Mile::Cirno::DefaultMaximumMessageSize;
            Request.Count -= Mile::Cirno::ReadDirResponseHeaderSize;
            Mile::Cirno::ReadDirResponse Response =
                g_Instance->ReadDir(Request);
            if (Response.Data.size() > 2)
            {
                result = STATUS_DIRECTORY_NOT_EMPTY;
            }
            else
            {
                result = STATUS_SUCCESS;
            }
        }
        catch (...) { }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoMoveFileW(
    _In_ LPCWSTR FileName,
    _In_ LPCWSTR NewFileName,
    _In_ BOOL ReplaceIfExisting,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(ReplaceIfExisting);

    auto start_time = std::chrono::steady_clock::now();

    NTSTATUS result = STATUS_NOT_IMPLEMENTED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    if (MILE_CIRNO_NOFID != FileId)
    {
        std::filesystem::path OldFilePath(&FileName[1]);
        std::filesystem::path NewFilePath(&NewFileName[1]);

        try
        {
            Mile::Cirno::WalkRequest OldDirectoryWalkRequest;
            OldDirectoryWalkRequest.FileId = g_RootDirectoryFileId;
            OldDirectoryWalkRequest.NewFileId = g_Instance->AllocateFileId();
            for (std::filesystem::path const& Element : OldFilePath)
            {
                if (Element == OldFilePath.filename())
                {
                    break;
                }
                OldDirectoryWalkRequest.Names.push_back(Element.string());
            }

            auto OldDirectoryWalkCleanupHandler = Mile::ScopeExitTaskHandler([&]()
                {
                    if (MILE_CIRNO_NOFID != OldDirectoryWalkRequest.NewFileId)
                    {
                        try
                        {
                            Mile::Cirno::ClunkRequest ClunkRequest;
                            ClunkRequest.FileId = OldDirectoryWalkRequest.NewFileId;
                            g_Instance->Clunk(ClunkRequest);
                        }
                        catch (...) { }
                        g_Instance->FreeFileId(OldDirectoryWalkRequest.NewFileId);
                    }
                });

            g_Instance->Walk(OldDirectoryWalkRequest);

            Mile::Cirno::WalkRequest NewDirectoryWalkRequest;
            NewDirectoryWalkRequest.FileId = g_RootDirectoryFileId;
            NewDirectoryWalkRequest.NewFileId = g_Instance->AllocateFileId();
            for (std::filesystem::path const& Element : NewFilePath)
            {
                if (Element == NewFilePath.filename())
                {
                    break;
                }
                NewDirectoryWalkRequest.Names.push_back(Element.string());
            }

            auto NewDirectoryWalkCleanupHandler = Mile::ScopeExitTaskHandler([&]()
                {
                    if (MILE_CIRNO_NOFID != NewDirectoryWalkRequest.NewFileId)
                    {
                        try
                        {
                            Mile::Cirno::ClunkRequest ClunkRequest;
                            ClunkRequest.FileId = NewDirectoryWalkRequest.NewFileId;
                            g_Instance->Clunk(ClunkRequest);
                        }
                        catch (...) { }
                        g_Instance->FreeFileId(NewDirectoryWalkRequest.NewFileId);
                    }
                });

            g_Instance->Walk(NewDirectoryWalkRequest);

            Mile::Cirno::RenameAtRequest Request;
            Request.OldDirectoryFileId = OldDirectoryWalkRequest.NewFileId;
            Request.OldName = OldFilePath.filename().string();
            Request.NewDirectoryFileId = NewDirectoryWalkRequest.NewFileId;
            Request.NewName = NewFilePath.filename().string();
            g_Instance->RenameAt(Request);

            result = STATUS_SUCCESS;
        }
        catch (...) { }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoSetEndOfFile(
    _In_ LPCWSTR FileName,
    _In_ LONGLONG ByteOffset,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    auto start_time = std::chrono::steady_clock::now();

    NTSTATUS result = STATUS_NOT_IMPLEMENTED;

    std::uint32_t FileId = static_cast<std::uint32_t>(DokanFileInfo->Context);

    if (MILE_CIRNO_NOFID != FileId)
    {
        try
        {
            Mile::Cirno::SetAttrRequest Request = { 0 };
            Request.FileId = FileId;
            Request.Valid = MileCirnoLinuxSetAttrFlagSize;
            Request.FileSize = ByteOffset;
            g_Instance->SetAttr(Request);

            result = STATUS_SUCCESS;
        }
        catch (...) { }
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return result;
}

NTSTATUS DOKAN_CALLBACK MileCirnoSetAllocationSize(
    _In_ LPCWSTR FileName,
    _In_ LONGLONG AllocSize,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(AllocSize);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoGetDiskFreeSpace(
    _Out_opt_ PULONGLONG FreeBytesAvailable,
    _Out_opt_ PULONGLONG TotalNumberOfBytes,
    _Out_opt_ PULONGLONG TotalNumberOfFreeBytes,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(DokanFileInfo);

    auto start_time = std::chrono::steady_clock::now();

    try
    {
        Mile::Cirno::StatFsRequest Request;
        Request.FileId = g_RootDirectoryFileId;
        Mile::Cirno::StatFsResponse Response = g_Instance->StatFs(Request);
        if (FreeBytesAvailable)
        {
            *FreeBytesAvailable = Response.BlockSize * Response.AvailableBlocks;
        }
        if (TotalNumberOfBytes)
        {
            *TotalNumberOfBytes = Response.BlockSize * Response.TotalBlocks;
        }
        if (TotalNumberOfFreeBytes)
        {
            *TotalNumberOfFreeBytes = Response.BlockSize * Response.FreeBlocks;
        }
    }
    catch (...)
    {
        RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

        return STATUS_NOT_IMPLEMENTED;
    }

    RecordBenchmarkData(__FUNCTION__, std::chrono::steady_clock::now() - start_time);

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoGetVolumeInformationW(
    LPWSTR VolumeNameBuffer,
    DWORD VolumeNameSize,
    LPDWORD VolumeSerialNumber,
    LPDWORD MaximumComponentLength,
    LPDWORD FileSystemFlags,
    LPWSTR FileSystemNameBuffer,
    DWORD FileSystemNameSize,
    PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(DokanFileInfo);

    if (VolumeNameBuffer)
    {
        ::wcsncpy_s(VolumeNameBuffer, VolumeNameSize / sizeof(WCHAR), Mile::ToWideString(CP_UTF8, g_AccessName).c_str(), _TRUNCATE);
    }
    if (VolumeSerialNumber)
    {
        *VolumeSerialNumber = GenerateFNV1AChecksum(g_AccessName);
    }
    if (MaximumComponentLength)
    {
        *MaximumComponentLength = 255;
    }
    if (FileSystemFlags)
    {
        *FileSystemFlags = FILE_UNICODE_ON_DISK;

        if (g_Options.Options & DOKAN_OPTION_CASE_SENSITIVE)
            *FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH;
    }
    if (FileSystemNameBuffer)
    {
        ::wcsncpy_s(FileSystemNameBuffer, FileSystemNameSize / sizeof(WCHAR), L"NTFS", _TRUNCATE);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoGetFileSecurityW(
    _In_ LPCWSTR FileName,
    _In_ PSECURITY_INFORMATION SecurityInformation,
    _Out_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG BufferLength,
    _Out_ PULONG LengthNeeded,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(SecurityInformation);
    UNREFERENCED_PARAMETER(SecurityDescriptor);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(LengthNeeded);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS DOKAN_CALLBACK MileCirnoSetFileSecurityW(
    _In_ LPCWSTR FileName,
    _In_ PSECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG BufferLength,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(SecurityInformation);
    UNREFERENCED_PARAMETER(SecurityDescriptor);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    return STATUS_SUCCESS;
}

int main()
{
    std::vector<std::string> Arguments = Mile::SplitCommandLineString(
        Mile::ToString(CP_UTF8, ::GetCommandLineW()));

    bool ParseSuccess = false;
    bool Mount = false;
    std::string Host;
    std::string Port;
    std::string ReadOnly;
    std::string CaseSensitive;

    if (0 == ::_stricmp(Arguments[1].c_str(), "Mount"))
    {
        if (9 == Arguments.size() &&
            0 == ::_stricmp(Arguments[2].c_str(), "TCP"))
        {
            ParseSuccess = true;
            Mount = true;
            Host = Arguments[3];
            Port = Arguments[4];
            g_AccessName = Arguments[5];
            g_MountPoint = Arguments[6];
            ReadOnly = Arguments[7];
            CaseSensitive = Arguments[8];
        }
        else if (8 == Arguments.size() &&
            0 == ::_stricmp(Arguments[2].c_str(), "HvSocket"))
        {
            ParseSuccess = true;
            Mount = true;
            Host = "HvSocket";
            Port = Arguments[3];
            g_AccessName = Arguments[4];
            g_MountPoint = Arguments[5];
            ReadOnly = Arguments[6];
            CaseSensitive = Arguments[7];
        }
    }
    else if (0 == ::_stricmp(Arguments[1].c_str(), "Unmount"))
    {
        if (3 == Arguments.size())
        {
            ParseSuccess = true;
            Mount = false;
            g_MountPoint = Arguments[2];
        }
    }

    if (!ParseSuccess)
    {
        return 0;
    }

    if (Mount)
    {
        auto CleanupHandler = Mile::ScopeExitTaskHandler([&]()
            {
                if (g_Instance)
                {
                    if (MILE_CIRNO_NOFID == g_RootDirectoryFileId)
                    {
                        g_Instance->FreeFileId(g_RootDirectoryFileId);
                    }
                    delete g_Instance;
                    g_Instance = nullptr;
                }

                ::WSACleanup();

                ::DokanShutdown();

                ::DokanRemoveMountPoint(Mile::ToWideString(CP_UTF8, g_MountPoint).c_str());
            });

        ::DokanInit();

        WSADATA WSAData = { 0 };
        {
            int WSAError = ::WSAStartup(MAKEWORD(2, 2), &WSAData);
            if (NO_ERROR != WSAError)
            {
                return -1;
            }
        }

        try
        {
            {
                if (0 == ::_stricmp(Host.c_str(), "HvSocket"))
                {
                    g_Instance = Mile::Cirno::Client::ConnectWithHyperVSocket(
                        Mile::ToUInt32(Port));
                }
                else
                {
                    g_Instance = Mile::Cirno::Client::ConnectWithTcpSocket(Host, Port);
                }
            }
            if (!g_Instance)
            {
                Mile::Cirno::ThrowException(
                    "!Instance",
                    ERROR_INVALID_DATA);
            }

            {
                Mile::Cirno::VersionRequest Request;
                Request.MaximumMessageSize =
                    Mile::Cirno::DefaultMaximumMessageSize;
                Request.ProtocolVersion =
                    Mile::Cirno::DefaultProtocolVersion;
                Mile::Cirno::VersionResponse Response =
                    g_Instance->Version(Request);
            }

            {
                Mile::Cirno::AttachRequest Request;
                Request.FileId = g_Instance->AllocateFileId();
                Request.AuthenticationFileId = MILE_CIRNO_NOFID;
                Request.UserName = "";
                Request.AccessName = g_AccessName;
                Request.NumericUserName = MILE_CIRNO_NONUNAME;
                Mile::Cirno::AttachResponse Response = g_Instance->Attach(Request);
                g_RootDirectoryFileId = Request.FileId;
            }
        }
        catch (...)
        {
            return -1;
        }

        std::wstring ConvertedMountPoint = Mile::ToWideString(CP_UTF8, g_MountPoint);

        g_Options.Version = DOKAN_VERSION;
        g_Options.SingleThread;
        g_Options.Options =
            (_stricmp(ReadOnly.c_str(), "true") == 0 ? DOKAN_OPTION_WRITE_PROTECT : 0) |
            (_stricmp(CaseSensitive.c_str(), "true") == 0 ? DOKAN_OPTION_CASE_SENSITIVE : 0) |
            DOKAN_OPTION_MOUNT_MANAGER;
        g_Options.GlobalContext;
        g_Options.MountPoint = ConvertedMountPoint.c_str();
        g_Options.UNCName;
        g_Options.Timeout = INFINITE;
        g_Options.AllocationUnitSize;
        g_Options.SectorSize;
        g_Options.VolumeSecurityDescriptorLength;
        g_Options.VolumeSecurityDescriptor;

        DOKAN_OPERATIONS Operations = { 0 };
        Operations.ZwCreateFile = ::MileCirnoZwCreateFile;
        Operations.Cleanup = ::MileCirnoCleanup;
        Operations.CloseFile = ::MileCirnoCloseFile;
        Operations.ReadFile = ::MileCirnoReadFile;
        Operations.WriteFile = ::MileCirnoWriteFile;
        Operations.FlushFileBuffers = ::MileCirnoFlushFileBuffers;
        Operations.GetFileInformation = ::MileCirnoGetFileInformation;
        Operations.FindFiles = ::MileCirnoFindFiles;
        Operations.SetFileAttributesW = ::MileCirnoSetFileAttributesW;
        Operations.SetFileTime = ::MileCirnoSetFileTime;
        Operations.DeleteFileW = ::MileCirnoDeleteFileW;
        Operations.DeleteDirectory = ::MileCirnoDeleteDirectory;
        Operations.MoveFileW = ::MileCirnoMoveFileW;
        Operations.SetEndOfFile = ::MileCirnoSetEndOfFile;
        Operations.SetAllocationSize = ::MileCirnoSetAllocationSize;
        Operations.GetDiskFreeSpaceW = ::MileCirnoGetDiskFreeSpace;
        Operations.GetVolumeInformationW = ::MileCirnoGetVolumeInformationW;
        Operations.GetFileSecurityW = ::MileCirnoGetFileSecurityW;
        Operations.SetFileSecurityW = ::MileCirnoSetFileSecurityW;
        Operations.FindStreams;
        return ::DokanMain(&g_Options, &Operations);
    }
    else
    {
        ::DokanRemoveMountPoint(Mile::ToWideString(CP_UTF8, g_MountPoint).c_str());
    }
}
