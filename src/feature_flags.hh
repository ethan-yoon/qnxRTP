#pragma once

/* Feature detection for optional subsystems that are intentionally missing. */

#ifndef UVGRTP_HAS_SRTP
#if defined(__has_include)
#if __has_include("srtp/base.hh")
#define UVGRTP_HAS_SRTP 1
#else
#define UVGRTP_HAS_SRTP 0
#endif
#else
#define UVGRTP_HAS_SRTP 0
#endif
#endif

#ifndef UVGRTP_HAS_ZRTP
#if defined(__has_include)
#if __has_include("zrtp/zrtp_receiver.hh")
#define UVGRTP_HAS_ZRTP 1
#else
#define UVGRTP_HAS_ZRTP 0
#endif
#else
#define UVGRTP_HAS_ZRTP 0
#endif
#endif

#ifndef UVGRTP_HAS_RTCP_READER
#if defined(__has_include)
#if __has_include("rtcp_reader.hh")
#define UVGRTP_HAS_RTCP_READER 1
#else
#define UVGRTP_HAS_RTCP_READER 0
#endif
#else
#define UVGRTP_HAS_RTCP_READER 0
#endif
#endif

#ifndef UVGRTP_HAS_RTCP
/* RTCP implementation is optional and may be intentionally omitted. */
#define UVGRTP_HAS_RTCP 0
#endif
