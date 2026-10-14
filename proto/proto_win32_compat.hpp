#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#ifdef DeleteFile
#undef DeleteFile
#endif
#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif
#if defined(_MSC_VER)
#pragma warning(disable: 4267) // conversion from 'size_t' to 'int', possible loss of data in protobuf generated code
#pragma warning(disable: 4244) // conversion from 'type1' to 'type2', possible loss of data
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wconversion"
#endif
#endif

