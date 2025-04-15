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
// server-other_openssl-srp-bof.cc author Brandon Stultz <brastult@cisco.com>

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

// TLS handshake types
#define HS_SERVER_HELLO 2  // server hello
#define HS_SERVER_KEYX  12 // server key exchange
#define HS_CLIENT_KEYX  16 // client key exchange

using namespace snort;

static const char* rule_59880 = R"[Snort_SO_Rule](
alert ssl (
    msg:"SERVER-OTHER OpenSSL SRP heap buffer overflow attempt";
    soid:59880;
    flow:established;
    ssl_state:server_hello,server_keyx,client_keyx;
    content:"|16 03|",depth 2;
    so:eval;
    metadata:policy max-detect-ips drop;
    reference:cve,2014-3512;
    reference:url,www.openssl.org/news/secadv/20140806.txt;
    classtype:attempted-admin;
    gid:3; sid:59880; rev:1;
)
)[Snort_SO_Rule]";

static const unsigned rule_59880_len = 0;

#if(BASE_API_VERSION > 1)

enum class SessionState
{
   Unknown,
   ServerHello,
   ServerKeyX,
   ClientKeyX
};

class SRPFlowData : public RuleFlowData
{
public:
   SRPFlowData() : RuleFlowData(id) { }

   static void init()
   { id = FlowData::create_flow_data_id(); }

   size_t size_of() override
   { return sizeof(*this); }

public:
   static unsigned id;
   SessionState state = SessionState::Unknown;
   uint16_t prime_len = 0;
};

unsigned SRPFlowData::id = 0;

static bool isSRPServerHello(const uint8_t* cursor_normal,
   const uint8_t* end_of_buffer, Packet* p)
{
   // skip:
   //   handshake type (1 byte)
   //   length         (3 bytes)
   //   version        (2 bytes)
   //   random         (32 bytes)
   cursor_normal += 38;

   // check if we can read:
   //   session_id_len (1 byte)
   if(cursor_normal + 1 > end_of_buffer)
      return false;

   uint8_t session_id_len = *cursor_normal++;

   // check if we can skip session_id_len
   if(session_id_len > end_of_buffer - cursor_normal)
      return false;

   // skip session_id_len
   cursor_normal += session_id_len;

   // check if we can read:
   //   cipher_suite (2 bytes)
   if(cursor_normal + 2 > end_of_buffer)
      return false;

   uint16_t cipher_suite = read_big_16(cursor_normal);

   // check for SRP cipher_suite:
   //   0xC01A TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
   //   0xC01B TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
   //   0xC01C TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
   //   0xC01D TLS_SRP_SHA_WITH_AES_128_CBC_SHA
   //   0xC01E TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
   //   0xC01F TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
   //   0xC020 TLS_SRP_SHA_WITH_AES_256_CBC_SHA
   //   0xC021 TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
   //   0xC022 TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
   if(cipher_suite < 0xC01A || cipher_suite > 0xC022)
      return false;

   // SRP cipher_suite found, get the FlowData for this flow
   SRPFlowData* fd =
      (SRPFlowData*)p->flow->get_flow_data(SRPFlowData::id);

   // initialize and set the FlowData if it does not exist
   if(!fd)
   {
      fd = new SRPFlowData();
      p->flow->set_flow_data(fd);
   }

   fd->state = SessionState::ServerHello;
   return true;
}

static IpsOption::EvalStatus checkServerKeyX(const uint8_t* cursor_normal,
   const uint8_t* end_of_buffer, Packet* p)
{
   // get the FlowData for this flow
   SRPFlowData* fd =
      (SRPFlowData*)p->flow->get_flow_data(SRPFlowData::id);

   // if no FlowData, not a SRP session, bail.
   if(!fd)
      return IpsOption::NO_MATCH;

   // check session state
   if(fd->state != SessionState::ServerHello)
      return IpsOption::NO_MATCH;

   fd->state = SessionState::ServerKeyX;

   // skip:
   //   handshake type (1 byte)
   //   length         (3 bytes)
   cursor_normal += 4;

   // check if we can read:
   //   prime_len (2 bytes)
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   fd->prime_len = read_big_16(cursor_normal);

   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus checkClientKeyX(const uint8_t* cursor_normal,
   const uint8_t* end_of_buffer, Packet* p)
{
   // get the FlowData for this flow
   SRPFlowData* fd =
      (SRPFlowData*)p->flow->get_flow_data(SRPFlowData::id);

   // if no FlowData, not a SRP session, bail.
   if(!fd)
      return IpsOption::NO_MATCH;

   // check session state
   if(fd->state != SessionState::ServerKeyX)
      return IpsOption::NO_MATCH;

   fd->state = SessionState::ClientKeyX;

   // skip:
   //   handshake type (1 byte)
   //   length         (3 bytes)
   cursor_normal += 4;

   // check if we can read:
   //   pub_val_len (2 bytes)
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   uint16_t pub_val_len = read_big_16(cursor_normal);

   // if pub_val_len > prime_len, alert.
   if(pub_val_len > fd->prime_len)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   if(!p->flow)
      return IpsOption::NO_MATCH;

   // check up to 5 records
   for(size_t i = 0; i < 5; i++)
   {
      // TLS record:
      //   type    (1 byte)
      //   version (2 bytes)
      //   length  (2 bytes)
      //   Handshake Protocol record:
      //     handshake type (1 byte)
      if(cursor_normal + 6 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // skip type (1 byte)
      cursor_normal += 1;

      // read version (2 bytes)
      uint16_t version = read_big_16_inc(cursor_normal);

      // check version
      //   0x0301 TLSv1.0
      //   0x0302 TLSv1.1
      //   0x0303 TLSv1.2
      if(version < 0x0301 || version > 0x0303)
         return IpsOption::NO_MATCH;

      // read length (2 bytes)
      uint16_t length = read_big_16_inc(cursor_normal);

      // read handshake type (1 byte)
      uint8_t hs_type = *cursor_normal;

      switch(hs_type)
      {
      case HS_SERVER_HELLO:
         if(!isSRPServerHello(cursor_normal, end_of_buffer, p))
            return IpsOption::NO_MATCH;
         else
            break;
      case HS_SERVER_KEYX:
         return checkServerKeyX(cursor_normal, end_of_buffer, p);
      case HS_CLIENT_KEYX:
         return checkClientKeyX(cursor_normal, end_of_buffer, p);
      default:
         break;
      }

      // check if we can skip length
      if(length > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip length
      cursor_normal += length;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    SRPFlowData::init();
    *pv = nullptr;
    return eval;
}

#else

static IpsOption::EvalStatus eval(void*, Cursor&, Packet*)
{
    return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

#endif

static const SoApi so_59880 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        1, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "59880", // name
        "SERVER-OTHER OpenSSL SRP heap buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_59880,
    rule_59880_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_59880 = &so_59880.base;
