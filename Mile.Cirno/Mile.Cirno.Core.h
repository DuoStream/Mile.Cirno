﻿/*
 * PROJECT:   Mouri Internal Library Essentials
 * FILE:      Mile.Cirno.Core.h
 * PURPOSE:   Definition for Mile.Cirno Core Infrastructures
 *
 * LICENSE:   The MIT License
 *
 * MAINTAINER: MouriNaruto (Kenji.Mouri@outlook.com)
 *             per1cycle (pericycle.cc@gmail.com)
 */

#ifndef MILE_CIRNO_CORE

#include "Mile.Cirno.Protocol.h"

#include <map>
#include <mutex>

namespace Mile::Cirno
{
    [[noreturn]] void ThrowException(
        std::string_view Checkpoint,
        std::int32_t const& Code);

    class Client
    {
    private:

        SOCKET m_Socket = INVALID_SOCKET;
        std::mutex m_ReceiveWorkerMutex;
        HANDLE m_ReceiveWorkerThread = nullptr;
        bool m_ReceiveWorkerStarted = false;
        std::map<std::uint16_t, std::vector<std::uint8_t>> m_Responses;

        Client() = default;

    public:

        void ReceiveWorkerEntryPoint();

        ~Client();

        void SendPacket(
            std::vector<std::uint8_t> const& Content);

        void WaitResponse(
            std::uint16_t const& Tag,
            std::vector<std::uint8_t>& Content);

        static Client* ConnectWithTcpSocket(
            std::string const& Host,
            std::string const& Port);

        static Client* ConnectWithHyperVSocket(
            std::uint32_t const& Port);
    };

    std::uint16_t AllocateTag();

    void FreeTag(
        std::uint16_t const& Tag);
}

#endif // !MILE_CIRNO_CORE
