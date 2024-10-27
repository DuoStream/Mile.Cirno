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

namespace Mile::Cirno
{
    std::uint16_t AllocateTag();

    void FreeTag(
        std::uint16_t const& Tag);
}

#endif // !MILE_CIRNO_CORE
