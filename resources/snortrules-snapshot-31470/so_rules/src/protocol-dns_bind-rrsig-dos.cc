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
// protocol-dns_bind-rrsig-dos.cc author Brandon Stultz <brastult@cisco.com>

#include "framework/cursor.h"
#include "framework/so_rule.h"
#include "main/snort_types.h"
#include "protocols/packet.h"
#include "util_dns.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_57953 = R"[Snort_SO_Rule](
alert udp any 53 -> $HOME_NET any (
    msg:"PROTOCOL-DNS ISC BIND RRSIG response processing denial of service attempt";
    soid:57953;
    flow:to_client;
    content:"|00 01|",depth 2,offset 4;
    content:"|00 2E 00 01|",distance 0;
    content:"|00 27|",within 2,distance 6;
    so:eval;
    metadata:policy max-detect-ips drop;
    service:dns;
    reference:cve,2016-1286;
    reference:url,kb.isc.org/docs/aa-01353;
    classtype:attempted-dos;
    gid:3;
    sid:57953;
    rev:1;
)
)[Snort_SO_Rule]";

static const unsigned rule_57953_len = 0;

static constexpr uint16_t DNS_TYPE_RRSIG = 0x002E;
static constexpr uint16_t DNS_TYPE_DNAME = 0x0027;

static IpsOption::EvalStatus rule_57953_eval(void*, Cursor& c, Packet*)
{
    const uint8_t *cursor_normal = c.buffer(),
                  *end_of_buffer = c.endo();

    // skip txid (2 bytes)
    cursor_normal += 2;

    // check if we can:
    //  read flags (2 bytes)
    //  skip question number (2 bytes)
    //  read answer number (2 bytes)
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
    //   `- response (1 = response)
    //
    if((flags & 0xFA0F) != 0x8000)
        return IpsOption::NO_MATCH;

    // skip question number (we limit it to 1)
    cursor_normal += 2;

    // get the number of answers
    uint16_t num_answers = read_big_16_inc(cursor_normal);

    // if num_answers > 5, bail
    if(num_answers > 5)
        return IpsOption::NO_MATCH;

    // skip:
    //  authority RR number (2 bytes)
    //  additional RR number (2 bytes)
    cursor_normal += 4;

    // skip query Name (we limit to 1)
    if(!skip_dns_name(cursor_normal, end_of_buffer))
        return IpsOption::NO_MATCH;

    // skip:
    //  query type (2 bytes)
    //  query class (2 bytes)
    cursor_normal += 4;

    bool dname_sig = false;
    bool dname_rec = false;

    for(unsigned i = 0; i < num_answers; ++i)
    {
        // skip answer
        if(!skip_dns_name(cursor_normal, end_of_buffer))
            return IpsOption::NO_MATCH;

        // check if we can:
        //  read type (2 bytes)
        //  skip class (2 bytes)
        //  skip TTL (4 bytes)
        //  read length (2 bytes)
        if(cursor_normal + 10 > end_of_buffer)
            return IpsOption::NO_MATCH;

        uint16_t type = read_big_16_inc(cursor_normal);

        // skip:
        //  class (2 bytes)
        //  TTL (4 bytes)
        cursor_normal += 6;

        uint16_t length = read_big_16_inc(cursor_normal);

        switch(type)
        {
        case DNS_TYPE_RRSIG:
        {
            // check if we can read:
            //  type covered (2 bytes)
            if(cursor_normal + 2 > end_of_buffer)
                return IpsOption::NO_MATCH;

            uint16_t type_covered = read_big_16(cursor_normal);

            if(type_covered == DNS_TYPE_DNAME)
                dname_sig = true;

            break;
        }
        case DNS_TYPE_DNAME:
            dname_rec = true;
            break;
        default:
            break;
        }

        // check if we can jump length
        if(length > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

        cursor_normal += length;
    }

    // if DNAME is signed but not present, alert.
    if(dname_sig && !dname_rec)
        return IpsOption::MATCH;

    return IpsOption::NO_MATCH;
}

static SoEvalFunc rule_57953_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_57953_eval;
}

static const SoApi so_57953 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        1, // version
        API_RESERVED,
        API_OPTIONS,
        "57953", // name
        "PROTOCOL-DNS ISC BIND RRSIG response processing denial of service attempt", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_57953,
    rule_57953_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_57953_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_57953 = &so_57953.base;
