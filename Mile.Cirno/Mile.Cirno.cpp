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
#include <vector>
#include <string>

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
static LogComponents EnabledLogLevels = (LogComponents)(Errors | Warnings | Information);

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
            wchar_t* logMessage = (wchar_t*)_alloca(length * sizeof(wchar_t));

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

// Win32 time epoch is 00:00:00, January 1 1601.
// UNIX time epoch is 00:00:00, January 1 1970.
// There are 11644473600 seconds between these two epochs.
const std::uint64_t SecondsBetweenWin32TimeAndUnixTime = 11644473600ULL;

FILETIME ToFileTime(
    std::uint64_t UnixTimeSeconds,
    std::uint64_t UnixTimeNanoseconds)
{
    std::uint64_t RawResult = UnixTimeSeconds;
    RawResult += SecondsBetweenWin32TimeAndUnixTime;
    RawResult *= 1000 * 1000 * 10;
    RawResult += UnixTimeNanoseconds / 100;
    FILETIME Result;
    Result.dwLowDateTime = static_cast<DWORD>(RawResult);
    Result.dwHighDateTime = static_cast<DWORD>(RawResult >> 32);
    return Result;
}

namespace
{
    Mile::Cirno::Client* g_Instance = nullptr;
    std::uint32_t g_RootDirectoryFileId = MILE_CIRNO_NOFID;
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
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(ShareAccess);

    ACCESS_MASK ConvertedDesiredAccess = 0;
    DWORD ConvertedFlagsAndAttributes = 0;
    DWORD ConvertedCreationDisposition = 0;
    ::DokanMapKernelToUserCreateFileFlags(
        DesiredAccess,
        FileAttributes,
        CreateOptions,
        CreateDisposition,
        &ConvertedDesiredAccess,
        &ConvertedFlagsAndAttributes,
        &ConvertedCreationDisposition);

    Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"[DEBUG] FileName = %s\n", FileName);

    try
    {
        Mile::Cirno::WalkRequest WalkRequest;
        WalkRequest.FileId = g_RootDirectoryFileId;
        WalkRequest.NewFileId = g_Instance->AllocateFileId();
        std::filesystem::path RelativePath(&FileName[1]);
        for (std::filesystem::path const& Element : RelativePath)
        {
            WalkRequest.Names.push_back(Element.string());
        }
        g_Instance->Walk(WalkRequest);

        Mile::Cirno::GetAttrRequest GetAttrRequest;
        GetAttrRequest.FileId = WalkRequest.NewFileId;
        GetAttrRequest.RequestMask = MileCirnoLinuxGetAttrFlagMode;
        Mile::Cirno::GetAttrResponse GetAttrResponse =
            g_Instance->GetAttr(GetAttrRequest);

        bool RequestCreate = false;
        std::uint32_t Flags =
            MileCirnoLinuxOpenCreateFlagLargeFile |
            MileCirnoLinuxOpenCreateFlagCloseOnExecute;
        /*if ((GENERIC_READ | GENERIC_WRITE) & ConvertedDesiredAccess)
        {
            Flags |= MileCirnoLinuxOpenCreateFlagReadWrite;
        }
        else if (GENERIC_READ & ConvertedDesiredAccess)
        {
            Flags |= MileCirnoLinuxOpenCreateFlagReadOnly;
        }
        else if (GENERIC_WRITE & ConvertedDesiredAccess)
        {
            Flags |= MileCirnoLinuxOpenCreateFlagWriteOnly;
        }*/
        if (FILE_FLAG_OVERLAPPED & ConvertedFlagsAndAttributes)
        {
            Flags |= MileCirnoLinuxOpenCreateFlagNonBlock;
        }
        switch (ConvertedCreationDisposition)
        {
        case CREATE_NEW:
            RequestCreate = true;
            Flags |= MileCirnoLinuxOpenCreateFlagCreate;
            Flags |= MileCirnoLinuxOpenCreateFlagCreateOnlyWhenNotExist;
            break;
        case CREATE_ALWAYS:
            RequestCreate = true;
            Flags |= MileCirnoLinuxOpenCreateFlagCreate;
            break;
        case OPEN_EXISTING:
            break;
        case OPEN_ALWAYS:
            Flags |= MileCirnoLinuxOpenCreateFlagCreate;
            break;
        case TRUNCATE_EXISTING:
            Flags |= MileCirnoLinuxOpenCreateFlagTruncate;
            break;
        default:
            break;
        }
        if (S_IFDIR & GetAttrResponse.Mode)
        {
            Flags |= MileCirnoLinuxOpenCreateFlagDirectory;
        }

        {
            Mile::Cirno::LinuxOpenRequest Request;
            Request.FileId = WalkRequest.NewFileId;
            Request.Flags = Flags;
            g_Instance->LinuxOpen(Request);
        }

        DokanFileInfo->Context = WalkRequest.NewFileId;
        if (S_IFDIR & GetAttrResponse.Mode)
        {
            DokanFileInfo->IsDirectory = TRUE;
        }
    }
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
        return DokanFileInfo->IsDirectory
            ? STATUS_OBJECT_PATH_NOT_FOUND
            : STATUS_OBJECT_NAME_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

void DOKAN_CALLBACK MileCirnoCloseFile(
    _In_ LPCWSTR FileName,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    std::uint32_t FileId = static_cast<std::uint32_t>(
        DokanFileInfo->Context);
    if (MILE_CIRNO_NOFID != FileId)
    {
        return;
    }

    try
    {
        Mile::Cirno::ClunkRequest Request;
        Request.FileId = FileId;
        g_Instance->Clunk(Request);
        g_Instance->FreeFileId(FileId);
    }
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
    }
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

    std::uint32_t FileId = static_cast<std::uint32_t>(
        DokanFileInfo->Context);
    if (MILE_CIRNO_NOFID == FileId)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

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
    }
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
        return STATUS_NOT_IMPLEMENTED;
    }

    if (ReadLength)
    {
        *ReadLength = ProceededSize;
    }

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoGetFileInformation(
    _In_ LPCWSTR FileName,
    _Out_ LPBY_HANDLE_FILE_INFORMATION Buffer,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);

    std::uint32_t FileId = static_cast<std::uint32_t>(
        DokanFileInfo->Context);
    if (MILE_CIRNO_NOFID == FileId)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    std::memset(Buffer, 0, sizeof(BY_HANDLE_FILE_INFORMATION));

    try
    {
        Mile::Cirno::GetAttrRequest Request;
        Request.FileId = FileId;
        Request.RequestMask =
            MileCirnoLinuxGetAttrFlagMode |
            MileCirnoLinuxGetAttrFlagNumberOfHardLinks |
            MileCirnoLinuxGetAttrFlagLastAccessTime |
            MileCirnoLinuxGetAttrFlagLastWriteTime |
            MileCirnoLinuxGetAttrFlagSize;
        Mile::Cirno::GetAttrResponse Response = g_Instance->GetAttr(Request);

        if (S_IFDIR & Response.Mode)
        {
            Buffer->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        }

        Buffer->ftCreationTime;

        Buffer->ftLastAccessTime = ::ToFileTime(
            Response.LastAccessTimeSeconds,
            Response.LastAccessTimeNanoseconds);
        Buffer->ftLastWriteTime = ::ToFileTime(
            Response.LastWriteTimeSeconds,
            Response.LastWriteTimeNanoseconds);

        Buffer->dwVolumeSerialNumber;

        Buffer->nFileSizeHigh =
            static_cast<DWORD>(Response.FileSize >> 32);
        Buffer->nFileSizeLow =
            static_cast<DWORD>(Response.FileSize);

        Buffer->nNumberOfLinks =
            static_cast<DWORD>(Response.NumberOfHardLinks);

        Buffer->nFileIndexHigh;
        Buffer->nFileIndexLow;
    }
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
        return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoFindFiles(
    _In_ LPCWSTR FileName,
    _In_ PFillFindData FillFindData,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(FillFindData);

    if (!DokanFileInfo->IsDirectory)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    std::uint32_t FileId = static_cast<std::uint32_t>(
        DokanFileInfo->Context);
    if (MILE_CIRNO_NOFID == FileId)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    try
    {
        std::uint64_t LastOffset = 0;
        do
        {
            Mile::Cirno::ReadDirRequest Request;
            Request.FileId = FileId;
            Request.Offset = LastOffset;
            LastOffset = 0;
            Request.Count = Mile::Cirno::DefaultMaximumMessageSize;
            Request.Count -= Mile::Cirno::ReadDirResponseHeaderSize;
            Mile::Cirno::ReadDirResponse Response =
                g_Instance->ReadDir(Request);
            for (Mile::Cirno::DirectoryEntry const& Entry : Response.Data)
            {
                LastOffset = Entry.Offset;

                if ("." == Entry.Name || ".." == Entry.Name)
                {
                    continue;
                }

                WIN32_FIND_DATAW FindData = { 0 };
                FindData.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
                ::wcscpy_s(
                    FindData.cFileName,
                    Mile::ToWideString(CP_UTF8, Entry.Name).c_str());

                try
                {
                    Mile::Cirno::WalkRequest WalkRequest;
                    WalkRequest.FileId = FileId;
                    WalkRequest.NewFileId = g_Instance->AllocateFileId();
                    WalkRequest.Names.push_back(Entry.Name);
                    g_Instance->Walk(WalkRequest);
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
                            catch (std::exception const& ex)
                            {
                                Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
                            }
                            g_Instance->FreeFileId(WalkRequest.NewFileId);
                        }
                    });

                    Mile::Cirno::GetAttrRequest InformationRequest;
                    InformationRequest.FileId = WalkRequest.NewFileId;
                    InformationRequest.RequestMask =
                        MileCirnoLinuxGetAttrFlagMode |
                        MileCirnoLinuxGetAttrFlagNumberOfHardLinks |
                        MileCirnoLinuxGetAttrFlagLastAccessTime |
                        MileCirnoLinuxGetAttrFlagLastWriteTime |
                        MileCirnoLinuxGetAttrFlagSize;
                    Mile::Cirno::GetAttrResponse InformationResponse =
                        g_Instance->GetAttr(InformationRequest);

                    if (S_IFDIR & InformationResponse.Mode)
                    {
                        FindData.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
                    }

                    FindData.ftCreationTime;

                    FindData.ftLastAccessTime = ::ToFileTime(
                        InformationResponse.LastAccessTimeSeconds,
                        InformationResponse.LastAccessTimeNanoseconds);
                    FindData.ftLastWriteTime = ::ToFileTime(
                        InformationResponse.LastWriteTimeSeconds,
                        InformationResponse.LastWriteTimeNanoseconds);
                    FindData.nFileSizeHigh =
                        static_cast<DWORD>(InformationResponse.FileSize >> 32);
                    FindData.nFileSizeLow =
                        static_cast<DWORD>(InformationResponse.FileSize);
                }
                catch (std::exception const& ex)
                {
                    Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
                }

                FillFindData(&FindData, DokanFileInfo);
            }
        } while (LastOffset);
    }
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
        return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MileCirnoGetDiskFreeSpace(
    _Out_opt_ PULONGLONG FreeBytesAvailable,
    _Out_opt_ PULONGLONG TotalNumberOfBytes,
    _Out_opt_ PULONGLONG TotalNumberOfFreeBytes,
    _Inout_ PDOKAN_FILE_INFO DokanFileInfo)
{
    UNREFERENCED_PARAMETER(DokanFileInfo);

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
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
        return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

int main()
{
    Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"Mile.Cirno %hs (Build %hs)\n(c) Kenji Mouri. All rights reserved.\n\n", MILE_PROJECT_VERSION_UTF8_STRING, MILE_PROJECT_MACRO_TO_UTF8_STRING(MILE_PROJECT_VERSION_BUILD));

    std::vector<std::string> Arguments = Mile::SplitCommandLineString(
        Mile::ToString(CP_UTF8, ::GetCommandLineW()));

    bool ParseSuccess = false;
    bool ShowHelp = false;
    std::string Host;
    std::string Port;
    std::string AccessName;
    std::string MountPoint;

    if (Arguments.empty() || 1 == Arguments.size())
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"[INFO] Mile.Cirno will run as the NanaBox EnableHostDriverStore integration mode.\n[INFO] Use \"Mile.Cirno Help\" for more commands.\n\n");

        ParseSuccess = true;
        Host = "HvSocket";
        Port = "50001";
        AccessName = "HostDriverStore";

        wchar_t System32Directory[MAX_PATH] = { 0 };
        ::GetSystemDirectoryW(
            System32Directory,
            sizeof(System32Directory) / sizeof(*System32Directory));
        MountPoint = Mile::ToString(CP_UTF8, System32Directory);
        MountPoint += "\\HostDriverStore";
    }
    else if (0 == ::_stricmp(Arguments[1].c_str(), "Help"))
    {
        ParseSuccess = true;
        ShowHelp = true;
    }
    else if (0 == ::_stricmp(Arguments[1].c_str(), "Mount"))
    {
        if (7 == Arguments.size() &&
            0 == ::_stricmp(Arguments[2].c_str(), "TCP"))
        {
            ParseSuccess = true;
            Host = Arguments[3];
            Port = Arguments[4];
            AccessName = Arguments[5];
            MountPoint = Arguments[6];
        }
        else if (6 == Arguments.size() &&
            0 == ::_stricmp(Arguments[2].c_str(), "HvSocket"))
        {
            ParseSuccess = true;
            Host = "HvSocket";
            Port = Arguments[3];
            AccessName = Arguments[4];
            MountPoint = Arguments[5];
        }
    }

    if (!ParseSuccess)
    {
        ShowHelp = true;
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"[ERROR] Unrecognized command.\n\n");
    }

    if (ShowHelp)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData,
            L"Format: Mile.Cirno [Command] <Option1> <Option2> ...\n"
            L"\n"
            L"Commands:\n"
            L"\n"
            L"  Help - Show this content.\n"
            L"\n"
            L"  Mount TCP [Host] [Port] [AccessName] [MountPoint]\n"
            L"    - Mount the specific 9p share over TCP.\n"
            L"  Mount HvSocket [Port] [AccessName] [MountPoint]\n"
            L"    - Mount the specific 9p share over Hyper-V Socket.\n"
            L"\n"
            L"Notes:\n"
            L"  - All command options are case-insensitive.\n"
            L"  - Mile.Cirno will run as the NanaBox EnableHostDriverStore\n"
            L"    integration mode if you don't specify another command, which\n"
            L"    is equivalent to the following command:\n"
            L"      Mile.Cirno Mount HvSocket 50001 HostDriverStore "
            L"%%SystemRoot%%\\System32\\HostDriverStore"
            L"\n"
            L"Examples:\n"
            L"\n"
            L"  Mile.Cirno Mount TCP 192.168.1.234 12345 MyShare C:\\MyMount\n"
            L"  Mile.Cirno Mount HvSocket 50001 HostDriverStore Z:\\\n"
            L"\n");
        return 0;
    }

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
    });

    ::DokanInit();

    WSADATA WSAData = { 0 };
    {
        int WSAError = ::WSAStartup(MAKEWORD(2, 2), &WSAData);
        if (NO_ERROR != WSAError)
        {
            Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"[ERROR] WSAStartup failed (%d).\n", WSAError);
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
            Log(EVENTLOG_INFORMATION_TYPE, DebugData,
                L"[INFO] Response.ProtocolVersion = %hs\n"
                L"[INFO] Response.MaximumMessageSize = %u\n",
                Response.ProtocolVersion.c_str(),
                Response.MaximumMessageSize);
        }

        {
            Mile::Cirno::AttachRequest Request;
            Request.FileId = g_Instance->AllocateFileId();
            Request.AuthenticationFileId = MILE_CIRNO_NOFID;
            Request.UserName = "";
            Request.AccessName = AccessName;
            Request.NumericUserName = MILE_CIRNO_NONUNAME;
            Mile::Cirno::AttachResponse Response = g_Instance->Attach(Request);
            g_RootDirectoryFileId = Request.FileId;
            Log(EVENTLOG_INFORMATION_TYPE, DebugData,
                L"[INFO] Response.UniqueId.Path = 0x%016llX\n",
                Response.UniqueId.Path);
        }
    }
    catch (std::exception const& ex)
    {
        Log(EVENTLOG_INFORMATION_TYPE, DebugData, L"%hs\n", ex.what());
        return -1;
    }

    std::wstring ConvertedMountPoint = Mile::ToWideString(CP_UTF8, MountPoint);

    DOKAN_OPTIONS Options = { 0 };
    Options.Version = DOKAN_VERSION;
    Options.SingleThread;
    Options.Options =
        DOKAN_OPTION_WRITE_PROTECT |
        DOKAN_OPTION_MOUNT_MANAGER |
        DOKAN_OPTION_CASE_SENSITIVE;
    Options.GlobalContext;
    Options.MountPoint = ConvertedMountPoint.c_str();
    Options.UNCName;
    Options.Timeout = INFINITE;
    Options.AllocationUnitSize;
    Options.SectorSize;
    Options.VolumeSecurityDescriptorLength;
    Options.VolumeSecurityDescriptor;

    DOKAN_OPERATIONS Operations = { 0 };
    Operations.ZwCreateFile = ::MileCirnoZwCreateFile;
    Operations.Cleanup;
    Operations.CloseFile = ::MileCirnoCloseFile;
    Operations.ReadFile = ::MileCirnoReadFile;
    Operations.WriteFile;
    Operations.FlushFileBuffers;
    Operations.GetFileInformation = ::MileCirnoGetFileInformation;
    Operations.FindFiles = ::MileCirnoFindFiles;
    Operations.FindFilesWithPattern = nullptr;
    Operations.SetFileAttributesW;
    Operations.SetFileTime;
    Operations.DeleteFileW;
    Operations.DeleteDirectory;
    Operations.MoveFileW;
    Operations.SetEndOfFile;
    Operations.SetAllocationSize;
    Operations.LockFile;
    Operations.UnlockFile;
    Operations.GetDiskFreeSpaceW = ::MileCirnoGetDiskFreeSpace;
    Operations.GetVolumeInformationW;
    Operations.Mounted;
    Operations.Unmounted;
    Operations.GetFileSecurityW;
    Operations.SetFileSecurityW;
    Operations.FindStreams;
    return ::DokanMain(&Options, &Operations);
}
