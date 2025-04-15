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
// protocol-dns_dns-spoof-mismatched-txid.cc author Brandon Stultz <brastult@cisco.com>
//                                           author Patrick Mullen <pamullen@cisco.com>

#include <cstring>

#include "flow/flow.h"
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

static const char* rule_21354 = R"[Snort_SO_Rule](
alert udp $HOME_NET any -> any 53 (
    msg:"PROTOCOL-DNS query";
    soid:21354;
    flow:to_server;
    content:"|00 01 00 00 00 00 00 00|",depth 8,offset 4;
    so:eval;
    metadata:policy max-detect-ips alert;
    service:dns;
    reference:bugtraq,30131;
    reference:bugtraq,39910;
    reference:bugtraq,82230;
    reference:cve,2008-1447;
    reference:cve,2010-1690;
    reference:cve,2016-0742;
    reference:url,docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-037;
    reference:url,docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-024;
    reference:url,mailman.nginx.org/pipermail/nginx/2016-January/049700.html;
    classtype:protocol-command-decode;
    gid:3;
    sid:21354;
    rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_21354_len = 0;

static const char* rule_21355 = R"[Snort_SO_Rule](
alert udp any 53 -> $HOME_NET any (
    msg:"PROTOCOL-DNS cache poisoning attempt - mismatched txid";
    soid:21355;
    flow:to_client;
    content:"|00 01 00 01|",depth 4,offset 4;
    so:eval;
    metadata:policy max-detect-ips drop;
    service:dns;
    reference:bugtraq,30131;
    reference:bugtraq,39910;
    reference:bugtraq,82230;
    reference:cve,2008-1447;
    reference:cve,2010-1690;
    reference:cve,2016-0742;
    reference:url,docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-037;
    reference:url,docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-024;
    reference:url,mailman.nginx.org/pipermail/nginx/2016-January/049700.html;
    classtype:attempted-recon;
    gid:3;
    sid:21355;
    rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_21355_len = 0;

#if(BASE_API_VERSION > 1)

static constexpr size_t MAX_QUERY_LEN = 256;

class DnsQueryFlowData : public RuleFlowData
{
public:
    DnsQueryFlowData() : RuleFlowData(id) {}

    static void init()
    { id = FlowData::create_flow_data_id(); }

    size_t size_of() override
    { return sizeof(*this); }

public:
    static unsigned id;
    uint16_t txid = 0;
    size_t query_len = 0;
    uint8_t query[MAX_QUERY_LEN] = {};
};

unsigned DnsQueryFlowData::id = 0;

static IpsOption::EvalStatus rule_21354_eval(void*, Cursor& c, Packet* p)
{
    const uint8_t *cursor_normal = c.buffer(),
                  *end_of_buffer = c.endo();

    if(!p->flow)
        return IpsOption::NO_MATCH;

    // check if we can:
    //  read txid (2 bytes)
    //  read flags (2 bytes)
    //  skip question number (2 bytes)
    //  skip answer number (2 bytes)
    //  skip authority RR number (2 bytes)
    //  skip additional RR number (2 bytes)
    if(cursor_normal + 12 > end_of_buffer)
        return IpsOption::NO_MATCH;

    uint16_t txid = read_big_16_inc(cursor_normal);
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

    size_t query_len = end_of_buffer - cursor_normal;

    if(query_len == 0)
        return IpsOption::NO_MATCH;

    if(query_len > MAX_QUERY_LEN)
        query_len = MAX_QUERY_LEN;

    // get the FlowData for this flow
    DnsQueryFlowData* fd =
        (DnsQueryFlowData*)p->flow->get_flow_data(DnsQueryFlowData::id);

    // initialize and set the FlowData if it does not exist
    if(!fd)
    {
        fd = new DnsQueryFlowData();
        p->flow->set_flow_data(fd);
    }

    // store txid and query on flow
    fd->txid = txid;
    fd->query_len = query_len;
    memcpy(fd->query, cursor_normal, query_len);

    return IpsOption::NO_MATCH;
}

static SoEvalFunc rule_21354_ctor(const char* /*so*/, void** pv)
{
    if(!DnsQueryFlowData::id)
        DnsQueryFlowData::init();

    *pv = nullptr;
    return rule_21354_eval;
}

static IpsOption::EvalStatus rule_21355_eval(void*, Cursor& c, Packet* p)
{
    const uint8_t *cursor_normal = c.buffer(),
                  *end_of_buffer = c.endo();

    if(!p->flow)
        return IpsOption::NO_MATCH;

    // check if we can:
    //  read txid (2 bytes)
    //  read flags (2 bytes)
    //  skip question number (2 bytes)
    //  skip answer number (2 bytes)
    //  skip authority RR number (2 bytes)
    //  skip additional RR number (2 bytes)
    if(cursor_normal + 12 > end_of_buffer)
        return IpsOption::NO_MATCH;

    uint16_t txid = read_big_16_inc(cursor_normal);
    uint16_t flags = read_big_16_inc(cursor_normal);

    // flags
    //
    // mask:
    // 0b1111101000000000 = 0xFA00
    //   ^^   ^^^    ^
    //   ||   |||    |
    //   ||   |||    `- reply code
    //   ||   ||`- recursion and others
    //   ||   |`- truncated (0 = not truncated)
    //   ||   `- authoritative
    //   |`- opcode (0000 = standard query)
    //   `- response (1 = response)
    //
    if((flags & 0xFA00) != 0x8000)
        return IpsOption::NO_MATCH;

    // skip:
    //  question number (2 bytes)
    //  answer number (2 bytes)
    //  authority RR number (2 bytes)
    //  additional RR number (2 bytes)
    cursor_normal += 8;

    size_t data_avail = end_of_buffer - cursor_normal;

    if(data_avail == 0)
        return IpsOption::NO_MATCH;

    // get the FlowData for this flow
    DnsQueryFlowData* fd =
        (DnsQueryFlowData*)p->flow->get_flow_data(DnsQueryFlowData::id);

    // if no FlowData, bail.
    if(!fd)
        return IpsOption::NO_MATCH;

    // check if there is enough data to check the query
    if(data_avail < fd->query_len)
        return IpsOption::NO_MATCH;

    // check if query matches
    if(memcmp(cursor_normal, fd->query, fd->query_len))
        return IpsOption::NO_MATCH;

    // query matches, if txid doesn't match, alert.
    if(txid != fd->txid)
        return IpsOption::MATCH;

    return IpsOption::NO_MATCH;
}

static SoEvalFunc rule_21355_ctor(const char* /*so*/, void** pv)
{
    if(!DnsQueryFlowData::id)
        DnsQueryFlowData::init();

    *pv = nullptr;
    return rule_21355_eval;
}

#else

static IpsOption::EvalStatus rule_21354_eval(void*, Cursor&, Packet*)
{
    return IpsOption::NO_MATCH;
}

static SoEvalFunc rule_21354_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_21354_eval;
}

static IpsOption::EvalStatus rule_21355_eval(void*, Cursor&, Packet*)
{
    return IpsOption::NO_MATCH;
}

static SoEvalFunc rule_21355_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_21355_eval;
}

#endif

static const SoApi so_21354 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version
        API_RESERVED,
        API_OPTIONS,
        "21354", // name
        "PROTOCOL-DNS query", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_21354,
    rule_21354_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_21354_ctor, // ctor
    nullptr  // dtor
};

static const SoApi so_21355 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version
        API_RESERVED,
        API_OPTIONS,
        "21355", // name
        "PROTOCOL-DNS cache poisoning attempt - mismatched txid", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_21355,
    rule_21355_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_21355_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_21354 = &so_21354.base;
const BaseApi* pso_21355 = &so_21355.base;
