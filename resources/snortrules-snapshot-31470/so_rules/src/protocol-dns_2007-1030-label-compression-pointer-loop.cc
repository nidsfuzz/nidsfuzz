//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
//
// This file may contain proprietary rules that were created, tested and
// certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
// rules that were created by Sourcefire and other third parties and
// distributed under the GNU General Public License (the "GPL Rules").
// The VRT Certified Rules contained in this file are the property of
// Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
// The GPL Rules created by Sourcefire, Inc. are the property of
// Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
// Reserved. All other GPL Rules are owned and copyrighted by their
// respective owners (please see www.snort.org/contributors for a list
// of owners and their respective copyrights). In order to determine what
// rules are VRT Certified Rules or GPL Rules, please refer to the VRT
// Certified Rules License Agreement.
//--------------------------------------------------------------------------
// protocol-dns_2007-1030-label-compression-pointer-loop.cc author Brandon Stultz <brastult@cisco.com>
//                                                          author Patrick Mullen <pamullen@cisco.com>

#include "framework/cursor.h"
#include "framework/so_rule.h"
#include "main/snort_types.h"
#include "protocols/packet.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_23039 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET [53,5533] (
    msg:"PROTOCOL-DNS Multiple Vendors DNS name decompression denial of service attempt";
    soid:23039;
    flow:to_server;
    content:"|00 01 00 00 00 00 00 00|",depth 8,offset 4;
    so:eval;
    metadata:policy max-detect-ips drop,policy security-ips drop;
    service:dns;
    reference:bugtraq,13729;
    reference:bugtraq,22606;
    reference:cve,2005-0036;
    reference:cve,2007-1030;
    classtype:attempted-dos;
    gid:3;
    sid:23039;
    rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_23039_len = 0;

static const char* rule_23040 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET [53,5533] (
    msg:"PROTOCOL-DNS Multiple Vendors DNS name decompression denial of service attempt";
    soid:23040;
    flow:to_server,established;
    content:"|00 01 00 00 00 00 00 00|",depth 8,offset 6;
    so:eval;
    metadata:policy max-detect-ips drop,policy security-ips drop;
    service:dns;
    reference:bugtraq,13729;
    reference:bugtraq,22606;
    reference:cve,2005-0036;
    reference:cve,2007-1030;
    classtype:attempted-dos;
    gid:3;
    sid:23040;
    rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_23040_len = 0;

static IpsOption::EvalStatus DetectDNSLoop(const uint8_t* cursor_normal,
    const uint8_t* end_of_buffer)
{
    // check if we can:
    //  read flags (2 bytes)
    //  skip question number (2 bytes)
    //  skip answer number (2 bytes)
    //  skip authority RR number (2 bytes)
    //  skip additional RR number (2 bytes)
    if(cursor_normal + 10 > end_of_buffer)
        return IpsOption::NO_MATCH;

    uint16_t flags = read_big_16_inc(cursor_normal);

    // flags
    //
    // mask:
    // 0b1111101000001111 = 0xFA0F
    //   ^^   ^^^    ^
    //   ||   |||    |
    //   ||   |||    `- reply code (0000 = no error)
    //   ||   ||`- recursion and others
    //   ||   |`- truncated (0 = not truncated)
    //   ||   `- authoritative
    //   |`- opcode (0000 = standard query)
    //   `- response (0 = query)
    //
    if((flags & 0xFA0F) != 0)
        return IpsOption::NO_MATCH;

    // skip:
    //  question number (2 bytes)
    //  answer number (2 bytes)
    //  authority RR number (2 bytes)
    //  additional RR number (2 bytes)
    cursor_normal += 8;

    // check query for DNS pointer
    while(cursor_normal < end_of_buffer)
    {
        uint8_t b = *cursor_normal++;

        if(b == 0)
            break;

        if((b & 0xC0) == 0xC0)
            return IpsOption::MATCH;

        cursor_normal += b;
    }

    return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus rule_23039_eval(void*, Cursor& c, Packet*)
{
    const uint8_t *cursor_normal = c.buffer(),
                  *end_of_buffer = c.endo();

    // move cursor to flags
    cursor_normal += 2;

    return DetectDNSLoop(cursor_normal, end_of_buffer);
}

static SoEvalFunc rule_23039_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_23039_eval;
}

static const SoApi so_23039 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version
        API_RESERVED,
        API_OPTIONS,
        "23039", // name
        "PROTOCOL-DNS Multiple Vendors DNS name decompression denial of service attempt", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_23039,
    rule_23039_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_23039_ctor, // ctor
    nullptr  // dtor
};

static IpsOption::EvalStatus rule_23040_eval(void*, Cursor& c, Packet*)
{
    const uint8_t *cursor_normal = c.buffer(),
                  *end_of_buffer = c.endo();

    // move cursor to flags
    // in the TCP case, flags are at offset 4
    cursor_normal += 4;

    return DetectDNSLoop(cursor_normal, end_of_buffer);
}

static SoEvalFunc rule_23040_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_23040_eval;
}

static const SoApi so_23040 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version
        API_RESERVED,
        API_OPTIONS,
        "23040", // name
        "PROTOCOL-DNS Multiple Vendors DNS name decompression denial of service attempt", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_23040,
    rule_23040_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_23040_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_23039 = &so_23039.base;
const BaseApi* pso_23040 = &so_23040.base;
