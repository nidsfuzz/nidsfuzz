//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// server-other_openssl-cmp-time-dos.cc author Brandon Stultz <brastult@cisco.com>

#include <cstring>

#include "framework/cursor.h"
#include "framework/so_rule.h"
#include "main/snort_types.h"
#include "protocols/packet.h"
#include "util_read.h"
#include "utils/util_ber.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

#define BER_DATA(t) if(!ber.data(cursor_normal,t)) return IpsOption::NO_MATCH;
#define BER_SKIP(t) if(!ber.skip(cursor_normal,t)) return IpsOption::NO_MATCH;

// TLS record types
#define TLS_HS 22

// TLS handshake types
#define HS_CERT 11

// ASN.1 time types
#define ASN1_TIME_UTC 23
#define ASN1_TIME_GEN 24

using namespace snort;

static const char* rule_59646 = R"[Snort_SO_Rule](
alert ssl (
    msg:"SERVER-OTHER OpenSSL X509_cmp_time out of bounds read attempt";
    soid:59646;
    flow:to_client,established;
    ssl_state:server_hello,server_keyx;
    content:"|16 03|",depth 2;
    so:eval;
    metadata:policy max-detect-ips drop;
    reference:cve,2015-1789;
    reference:url,www.openssl.org/news/secadv/20150611.txt;
    classtype:attempted-dos;
    gid:3; sid:59646; rev:1;
)
)[Snort_SO_Rule]";

static const unsigned rule_59646_len = 0;

static bool hasSign(const uint8_t* buf, size_t len)
{
    if(len == 0)
        return false;

    if(memchr(buf, '+', len))
        return true;

    if(memchr(buf, '-', len))
        return true;

    return false;
}

static IpsOption::EvalStatus rule_59646_eval(void*, Cursor& c, Packet*)
{
    const uint8_t *cursor_normal = c.buffer(),
                  *end_of_buffer = c.endo();

    BerReader ber(c);

    // check if we can read the record length and type
    if(cursor_normal + 6 > end_of_buffer)
        return IpsOption::NO_MATCH;

    // skip the first HS if it is not a cert
    if(cursor_normal[5] != HS_CERT) {
        // skip:
        //  TLS Type (1 byte)
        //  TLS Version (2 byte)
        cursor_normal += 3;

        // read the record length
        uint16_t rec_len = read_big_16_inc(cursor_normal);

        // check if we can jump rec_len
        if(rec_len > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

        cursor_normal += rec_len;

        // check if we can read the next HS
        if(cursor_normal + 6 > end_of_buffer)
            return IpsOption::NO_MATCH;

        // verify we landed on a cert
        if(cursor_normal[5] != HS_CERT || cursor_normal[0] != TLS_HS)
            return IpsOption::NO_MATCH;
    }

    // skip:
    //  TLS Type (1 byte)
    //  Handshake Version (2 bytes)
    //  Handshake Length (2 bytes)
    //  Handshake Type (1 bytes)
    //  HS Proto Length (3 bytes)
    //  Certificates Length (3 bytes)
    //  and 1st Certificate Length (3 bytes)
    cursor_normal += 15;

    BER_DATA(0x30); // Certificate ::= SEQUENCE 0x30
    BER_DATA(0x30); //    tbsCertificate ::= SEQUENCE 0x30
    BER_SKIP(0xA0); //       version      0xA0
    BER_SKIP(0x02); //       serialNumber 0x02
    BER_SKIP(0x30); //       signature    SEQUENCE 0x30
    BER_SKIP(0x30); //       issuer       SEQUENCE 0x30
    BER_DATA(0x30); //       validity ::= SEQUENCE 0x30

    // validity ::= SEQUENCE {
    //    notBefore Time
    //    notAfter  Time
    // }
    //
    // Time ::= CHOICE {
    //    utcTime      UTCTime         0x17
    //    generalTime  GeneralizedTime 0x18
    // }

    // check the notBefore and notAfter times
    for(unsigned i = 0; i < 2; i++)
    {
        BerElement time;

        if(!ber.read(cursor_normal, time))
            return IpsOption::NO_MATCH;

        // time must be one of the supported types
        if(time.type != ASN1_TIME_UTC && time.type != ASN1_TIME_GEN)
            return IpsOption::NO_MATCH;

        // move cursor to the time data
        cursor_normal = time.data;

        uint32_t length = time.length;

        if(length == 0)
            continue;

        // check if we can read length
        if(length > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

        uint32_t offset = 0;

        if(length > 4)
            offset = length - 4;

        // if the offset sign is in the last 4 bytes, alert
        if(hasSign(cursor_normal + offset, length - offset))
            return IpsOption::MATCH;

        // jump length
        cursor_normal += length;
    }

    return IpsOption::NO_MATCH;
}

static SoEvalFunc rule_59646_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_59646_eval;
}

static const SoApi so_59646 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        1, // version
        API_RESERVED,
        API_OPTIONS,
        "59646", // name
        "SERVER-OTHER OpenSSL X509_cmp_time out of bounds read attempt", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_59646,
    rule_59646_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_59646_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_59646 = &so_59646.base;
