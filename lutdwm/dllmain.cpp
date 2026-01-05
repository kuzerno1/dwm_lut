// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <io.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#pragma comment (lib, "d3d11.lib") // Maybe un-useful
#pragma comment (lib, "d3dcompiler.lib")
#pragma comment (lib, "dxgi.lib") // Maybe un-useful
#pragma comment (lib, "uuid.lib") // Maybe un-useful
#pragma comment (lib, "dxguid.lib")


#pragma intrinsic(_ReturnAddress)

#define DITHER_GAMMA 2.2
#define LUT_FOLDER "%SYSTEMROOT%\\Temp\\luts"

#define RELEASE_IF_NOT_NULL(x) { if (x != NULL) { x->Release(); } }
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define RESIZE(x, y) realloc(x, (y) * sizeof(*x));
#define LOG_FILE_PATH R"(C:\DWMLOG\dwm.log)"
#define MAX_LOG_FILE_SIZE 20 * 1024 * 1024
// Enable diagnostics logging even in release builds for debugging pattern matching issues
#define ENABLE_DIAGNOSTICS true
#ifdef _DEBUG
#define DEBUG_MODE true
#else
#define DEBUG_MODE false
#endif

#if DEBUG_MODE == true
#define __LOG_ONLY_ONCE(x, y) if (static bool first_log_##y = true) { log_to_file(x); first_log_##y = false; }
#define _LOG_ONLY_ONCE(x, y) __LOG_ONLY_ONCE(x, y)
#define LOG_ONLY_ONCE(x) _LOG_ONLY_ONCE(x, __COUNTER__)
#define MESSAGE_BOX_DBG(x, y) MessageBoxA(NULL, x, "DEBUG HOOK DWM", y);

#define EXECUTE_WITH_LOG(winapi_func_hr) \
	do { \
		HRESULT hr = (winapi_func_hr); \
		if (FAILED(hr)) \
		{ \
			std::stringstream ss; \
			ss << "ERROR AT LINE: " << __LINE__ << " HR: " << hr << " - DETAILS: "; \
			LPSTR error_message = nullptr; \
			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
				NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_message, 0, NULL); \
			ss << error_message; \
			log_to_file(ss.str().c_str()); \
			LocalFree(error_message); \
			throw std::exception(ss.str().c_str()); \
		} \
	} while (false);

#define EXECUTE_D3DCOMPILE_WITH_LOG(winapi_func_hr, error_interface) \
	do { \
		HRESULT hr = (winapi_func_hr); \
		if (FAILED(hr)) \
		{ \
			std::stringstream ss; \
			ss << "ERROR AT LINE: " << __LINE__ << " HR: " << hr << " - DETAILS: "; \
			LPSTR error_message = nullptr; \
			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
				NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_message, 0, NULL); \
			ss << error_message << " - DX COMPILE ERROR: " << (char*)error_interface->GetBufferPointer(); \
			error_interface->Release(); \
			log_to_file(ss.str().c_str()); \
			LocalFree(error_message); \
			throw std::exception(ss.str().c_str()); \
		} \
	} while (false);

#define LOG_ADDRESS(prefix_message, address) \
	{ \
		std::stringstream ss; \
		ss << prefix_message << " 0x" << std::setw(sizeof(address) * 2) << std::setfill('0') << std::hex << (UINT_PTR)address; \
		log_to_file(ss.str().c_str()); \
	}

#else
#define LOG_ONLY_ONCE(x) // NOP, not in debug mode
#define MESSAGE_BOX_DBG(x, y) // NOP, not in debug mode
#define EXECUTE_WITH_LOG(winapi_func_hr) winapi_func_hr;
#define EXECUTE_D3DCOMPILE_WITH_LOG(winapi_func_hr, error_interface) winapi_func_hr;
#define LOG_ADDRESS(prefix_message, address) // NOP, not in debug mode
#endif

// Diagnostics logging that works in both debug and release builds
#if ENABLE_DIAGNOSTICS == true
void diag_log(const char* log_buf)
{
	// Create directory if needed
	CreateDirectoryA("C:\\DWMLOG", NULL);
	FILE* pFile = fopen("C:\\DWMLOG\\dwm_diag.log", "a");
	if (pFile == NULL) return;
	fseek(pFile, 0, SEEK_END);
	long size = ftell(pFile);
	if (size > MAX_LOG_FILE_SIZE)
	{
		if (_chsize(_fileno(pFile), 0) == -1)
		{
			fclose(pFile);
			return;
		}
	}
	fseek(pFile, 0, SEEK_END);

	// Add timestamp
	SYSTEMTIME st;
	GetLocalTime(&st);
	fprintf(pFile, "[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, log_buf);
	fclose(pFile);
}

void diag_log_bytes(const char* prefix, const unsigned char* bytes, size_t len)
{
	std::stringstream ss;
	ss << prefix;
	for (size_t i = 0; i < len && i < 32; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << " ";
	}
	if (len > 32) ss << "...";
	diag_log(ss.str().c_str());
}

// Pattern discovery: search for function prologues that match partial patterns
void discover_present_patterns(unsigned char* base, size_t size)
{
	diag_log("=== Pattern Discovery: Searching for COverlayContext::Present candidates ===");

	// Pattern 1: Standard W11 prologue (40 53 55 56 57 41 56 41 57 48 81 EC)
	const unsigned char partial1[] = { 0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC };
	int found = 0;
	for (size_t i = 0; i < size - 32 && found < 5; i++)
	{
		if (memcmp(base + i, partial1, sizeof(partial1)) == 0)
		{
			std::stringstream ss;
			ss << "  [Type1] Candidate at offset 0x" << std::hex << i << ": ";
			for (int j = 0; j < 32; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}

	// Pattern 2: Alternative prologue with 48 83 EC (smaller stack, sub rsp, imm8)
	const unsigned char partial2[] = { 0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC };
	for (size_t i = 0; i < size - 32 && found < 10; i++)
	{
		if (memcmp(base + i, partial2, sizeof(partial2)) == 0)
		{
			std::stringstream ss;
			ss << "  [Type2] Candidate at offset 0x" << std::hex << i << ": ";
			for (int j = 0; j < 32; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}

	// Pattern 3: Look for push rbx, push rbp, push rsi, push rdi with different REX prefixes
	const unsigned char partial3[] = { 0x48, 0x89, 0x5C, 0x24 }; // mov [rsp+xx], rbx - common prologue start
	for (size_t i = 0; i < size - 48 && found < 15; i++)
	{
		if (memcmp(base + i, partial3, sizeof(partial3)) == 0)
		{
			// Check if followed by typical prologue pattern (more mov's or push's)
			if (base[i + 5] == 0x48 || base[i + 5] == 0x4C || base[i + 5] == 0x55 || base[i + 5] == 0x56)
			{
				std::stringstream ss;
				ss << "  [Type3] Candidate at offset 0x" << std::hex << i << ": ";
				for (int j = 0; j < 48; j++)
					ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
				diag_log(ss.str().c_str());
				found++;
			}
		}
	}

	if (found == 0) diag_log("  No candidates found with any prologue type");
}

void discover_directflip_patterns(unsigned char* base, size_t size)
{
	diag_log("=== Pattern Discovery: Searching for IsCandidateDirectFlipCompatible candidates ===");
	// Look for: 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC xx (common DirectFlip prologue)
	const unsigned char partial[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC };
	int found = 0;
	for (size_t i = 0; i < size - 32 && found < 5; i++)
	{
		if (memcmp(base + i, partial, sizeof(partial)) == 0)
		{
			std::stringstream ss;
			ss << "  Candidate at offset 0x" << std::hex << i << ": ";
			for (int j = 0; j < 32; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}
	if (found == 0) diag_log("  No candidates found with standard prologue");
}

void discover_overlays_patterns(unsigned char* base, size_t size)
{
	diag_log("=== Pattern Discovery: Searching for OverlaysEnabled candidates ===");
	int found = 0;

	// Pattern 1: 83 3D ?? ?? ?? ?? ?? (74|75) 04 (cmp dword ptr [rip+xx], xx; jz/jnz 04)
	for (size_t i = 0; i < size - 16 && found < 10; i++)
	{
		if (base[i] == 0x83 && base[i + 1] == 0x3D &&
		    (base[i + 8] == 0x74 || base[i + 8] == 0x75) && base[i + 9] == 0x04)
		{
			std::stringstream ss;
			ss << "  [Type1] Candidate at offset 0x" << std::hex << i << ": ";
			for (int j = 0; j < 16; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}

	// Pattern 2: 83 3D ?? ?? ?? ?? ?? (74|75) 05 (jz/jnz +5 instead of +4)
	for (size_t i = 0; i < size - 16 && found < 15; i++)
	{
		if (base[i] == 0x83 && base[i + 1] == 0x3D &&
		    (base[i + 8] == 0x74 || base[i + 8] == 0x75) && base[i + 9] == 0x05)
		{
			std::stringstream ss;
			ss << "  [Type2] Candidate at offset 0x" << std::hex << i << ": ";
			for (int j = 0; j < 16; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}

	// Pattern 3: 39 1D ?? ?? ?? ?? (74|75) - cmp [rip+xx], ebx followed by conditional jump
	for (size_t i = 0; i < size - 16 && found < 20; i++)
	{
		if (base[i] == 0x39 && base[i + 1] == 0x1D &&
		    (base[i + 6] == 0x74 || base[i + 6] == 0x75))
		{
			std::stringstream ss;
			ss << "  [Type3-cmp ebx] Candidate at offset 0x" << std::hex << i << ": ";
			for (int j = 0; j < 16; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[i + j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}

	// Pattern 4: Look for small functions with xor al,al; ret or mov al,1; ret (typical bool returns)
	// Pattern: 32 C0 C3 (xor al, al; ret) or B0 01 C3 (mov al, 1; ret)
	for (size_t i = 8; i < size - 8 && found < 25; i++)
	{
		// Look for patterns like: 75 04 32 c0 c3 cc or 74 04 32 c0 c3 cc
		if ((base[i] == 0x74 || base[i] == 0x75) &&
		    base[i + 1] >= 0x02 && base[i + 1] <= 0x06 &&
		    base[i + 2] == 0x32 && base[i + 3] == 0xC0 && base[i + 4] == 0xC3)
		{
			// Look backwards for the cmp instruction
			std::stringstream ss;
			ss << "  [Type4-ret pattern] Found at offset 0x" << std::hex << i << ", checking context: ";
			size_t start = (i >= 10) ? i - 10 : 0;
			for (size_t j = start; j < i + 8; j++)
				ss << std::setw(2) << std::setfill('0') << (int)base[j] << " ";
			diag_log(ss.str().c_str());
			found++;
		}
	}

	if (found == 0) diag_log("  No candidates found");
}

#define DIAG_LOG(x) diag_log(x)
#define DIAG_LOG_BYTES(prefix, bytes, len) diag_log_bytes(prefix, bytes, len)
#define DISCOVER_PATTERNS(base, size) do { discover_present_patterns(base, size); discover_directflip_patterns(base, size); discover_overlays_patterns(base, size); } while(0)
#else
#define DIAG_LOG(x)
#define DIAG_LOG_BYTES(prefix, bytes, len)
#define DISCOVER_PATTERNS(base, size)
#endif


#if DEBUG_MODE == true
void print_error(const char* prefix_message)
{
	DWORD errorCode = GetLastError();
	LPSTR errorMessage = nullptr;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	               nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&errorMessage, 0, nullptr);

	char message_buf[100];
	sprintf(message_buf, "%s: %s - error code: %u", prefix_message, errorMessage, errorCode);
	MESSAGE_BOX_DBG(message_buf, MB_OK | MB_ICONWARNING)
	return;
}

void log_to_file(const char* log_buf)
{
	FILE* pFile = fopen(LOG_FILE_PATH, "a");
	if (pFile == NULL)
	{
		// print_error("Error during logging"); // Comment out to prevent UI freeze when used inside hooked functions
		return;
	}
	fseek(pFile, 0, SEEK_END);
	long size = ftell(pFile);
	if (size > MAX_LOG_FILE_SIZE)
	{
		if (_chsize(_fileno(pFile), 0) == -1)
		{
			fclose(pFile);
			return;
		}
	}
	fseek(pFile, 0, SEEK_END);
	fprintf(pFile, "%s\n", log_buf);
	fclose(pFile);
}
#endif


unsigned int lut_index(const unsigned int b, const unsigned int g, const unsigned int r, const unsigned int c,
                       const unsigned int lut_size)
{
	return lut_size * lut_size * 4 * b + lut_size * 4 * g + 4 * r + c;
}

#define LUT_ACCESS_INDEX(lut, b, g, r, c, lut_size) (*((float*)(lut) + lut_index(b, g, r, c, lut_size)))


const unsigned char COverlayContext_Present_bytes[] = {
	0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0x8b, 0xb1, 0x20,
	0x2c, 0x00, 0x00, 0x45, 0x8b, 0xd0, 0x48, 0x8b, 0xfa, 0x48, 0x8b, 0xd9, 0x48, 0x85, 0xf6, 0x0f, 0x85
};
const int IOverlaySwapChain_IDXGISwapChain_offset = -0x118;

const unsigned char COverlayContext_IsCandidateDirectFlipCompatbile_bytes[] = {
	0x48, 0x89, 0x7c, 0x24, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8b, 0xec, 0x48, 0x83,
	0xec, 0x40
};
const unsigned char COverlayContext_OverlaysEnabled_bytes[] = {
	0x75, 0x04, 0x32, 0xc0, 0xc3, 0xcc, 0x83, 0x79, 0x30, 0x01, 0x0f, 0x97, 0xc0, 0xc3
};

const int COverlayContext_DeviceClipBox_offset = -0x120;

const int IOverlaySwapChain_HardwareProtected_offset = -0xbc;

/*
 * AOB for function: COverlayContext_Present_bytes_w11
 *
 * 40 53 55 56 57 41 56 41 57 48 81 EC 88 00 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 78 48
 *
 */
const unsigned char COverlayContext_Present_bytes_w11[] = {
	0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05,
	'?', '?', '?', '?', 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, 0x78, 0x48
};
const int IOverlaySwapChain_IDXGISwapChain_offset_w11 = 0xE0;
const int IOverlaySwapChain_IDXGISwapChain_offset_w11_24H2 = 0xE8; // Updated offset for 24H2

/*
 * AOB for function: COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11
 *
 * 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 68 48
 */
const unsigned char COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11[] = {
	0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC,
	0x68, 0x48,
};

/*
 * AOB for function: COverlayContext_OverlaysEnabled_bytes_w11
 *
 * 83 3D ?? ?? ?? ?? ?? 75 04
 */
const unsigned char COverlayContext_OverlaysEnabled_bytes_w11[] = {
	0x83, 0x3D, '?', '?', '?', '?', '?', 0x75, 0x04
};

// Windows 11 24H2 AOB patterns - these may need to be updated based on actual dwmcore.dll signatures
const unsigned char COverlayContext_Present_bytes_w11_24H2[] = {
	0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05,
	'?', '?', '?', '?', 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, 0x80, 0x48
};

const unsigned char COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11_24H2[] = {
	0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC,
	0x70, 0x48,
};

const unsigned char COverlayContext_OverlaysEnabled_bytes_w11_24H2[] = {
	0x83, 0x3D, '?', '?', '?', '?', '?', 0x74, 0x04
};

/*
 * Windows 11 25H2 (Build 26200+) AOB patterns
 * Key changes from 24H2:
 * - Present: Uses 48 83 EC (sub rsp, imm8) instead of 48 81 EC (sub rsp, imm32)
 * - DirectFlip: Stack allocation changed from 0x70 to 0x78
 * - OverlaysEnabled: Pattern structure changed, now uses simpler check
 */

// Present pattern for 25H2 - uses smaller stack allocation instruction
// Pattern: 40 53 55 56 57 41 56 41 57 48 83 EC 68 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 50
const unsigned char COverlayContext_Present_bytes_w11_25H2[] = {
	0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x68, 0x48, 0x8B, 0x05,
	'?', '?', '?', '?', 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, 0x50
};

// DirectFlip pattern for 25H2 - stack allocation 0x78 instead of 0x70
const unsigned char COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11_25H2[] = {
	0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC,
	0x78, 0x48,
};

// OverlaysEnabled for 25H2 - uses test rax,rax; jnz pattern
// Pattern: 48 8B 41 38 48 85 C0 75 04 32 C0 C3
const unsigned char COverlayContext_OverlaysEnabled_bytes_w11_25H2[] = {
	0x48, 0x8B, 0x41, 0x38, 0x48, 0x85, 0xC0, 0x75, 0x04, 0x32, 0xC0, 0xC3
};

int COverlayContext_DeviceClipBox_offset_w11 = 0x466C;
int COverlayContext_DeviceClipBox_offset_w11_24H2 = 0x4680; // Updated offset for 24H2
int COverlayContext_DeviceClipBox_offset_w11_25H2 = 0x4680; // Same as 24H2, may need adjustment

const int IOverlaySwapChain_HardwareProtected_offset_w11 = -0x144;
const int IOverlaySwapChain_HardwareProtected_offset_w11_24H2 = -0x14C; // Updated offset for 24H2
const int IOverlaySwapChain_HardwareProtected_offset_w11_25H2 = -0x14C; // Same as 24H2, may need adjustment

const int IOverlaySwapChain_IDXGISwapChain_offset_w11_25H2 = 0xE8; // Same as 24H2, may need adjustment

bool isWindows11;
bool isWindows11_24H2;
bool isWindows11_25H2;

bool aob_match_inverse(const void* buf1, const void* mask, const int buf_len)
{
	for (int i = 0; i < buf_len; ++i)
	{
		if (((unsigned char*)buf1)[i] != ((unsigned char*)mask)[i] && ((unsigned char*)mask)[i] != '?')
		{
			return true;
		}
	}
	return false;
}

char shaders[] = R"(
    struct VS_INPUT {
	float2 pos : POSITION;
	float2 tex : TEXCOORD;
};

struct VS_OUTPUT {
	float4 pos : SV_POSITION;
	float2 tex : TEXCOORD;
};

Texture2D backBufferTex : register(t0);
Texture3D lutTex : register(t1);
SamplerState smp : register(s0);

Texture2D noiseTex : register(t2);
SamplerState noiseSmp : register(s1);

int lutSize : register(b0);
bool hdr : register(b0);

static float3x3 scrgb_to_bt2100 = {
2939026994.L / 585553224375.L, 9255011753.L / 3513319346250.L,   173911579.L / 501902763750.L,
  76515593.L / 138420033750.L, 6109575001.L / 830520202500.L,    75493061.L / 830520202500.L,
  12225392.L / 93230009375.L, 1772384008.L / 2517210253125.L, 18035212433.L / 2517210253125.L,
};

static float3x3 bt2100_to_scrgb = {
 348196442125.L / 1677558947.L, -123225331250.L / 1677558947.L,  -15276242500.L / 1677558947.L,
-579752563250.L / 37238079773.L, 5273377093000.L / 37238079773.L,  -38864558125.L / 37238079773.L,
 -12183628000.L / 5369968309.L, -472592308000.L / 37589778163.L, 5256599974375.L / 37589778163.L,
};

static float m1 = 1305 / 8192.;
static float m2 = 2523 / 32.;
static float c1 = 107 / 128.;
static float c2 = 2413 / 128.;
static float c3 = 2392 / 128.;

float3 SampleLut(float3 index) {
	float3 tex = (index + 0.5) / lutSize;
	return lutTex.Sample(smp, tex).rgb;
}

// adapted from https://doi.org/10.2312/egp.20211031
void barycentricWeight(float3 r, out float4 bary, out int3 vert2, out int3 vert3) {
	vert2 = int3(0, 0, 0); vert3 = int3(1, 1, 1);
	int3 c = r.xyz >= r.yzx;
	bool c_xy = c.x; bool c_yz = c.y; bool c_zx = c.z;
	bool c_yx = !c.x; bool c_zy = !c.y; bool c_xz = !c.z;
	bool cond;  float3 s = float3(0, 0, 0);
#define ORDER(X, Y, Z)                   \
            cond = c_ ## X ## Y && c_ ## Y ## Z; \
            s = cond ? r.X ## Y ## Z : s;        \
            vert2.X = cond ? 1 : vert2.X;        \
            vert3.Z = cond ? 0 : vert3.Z;
	ORDER(x, y, z)   ORDER(x, z, y)   ORDER(z, x, y)
		ORDER(z, y, x)   ORDER(y, z, x)   ORDER(y, x, z)
		bary = float4(1 - s.x, s.z, s.x - s.y, s.y - s.z);
}

float3 LutTransformTetrahedral(float3 rgb) {
	float3 lutIndex = rgb * (lutSize - 1);
	float4 bary; int3 vert2; int3 vert3;
	barycentricWeight(frac(lutIndex), bary, vert2, vert3);

	float3 base = floor(lutIndex);
	return bary.x * SampleLut(base) +
		bary.y * SampleLut(base + 1) +
		bary.z * SampleLut(base + vert2) +
		bary.w * SampleLut(base + vert3);
}

float3 pq_eotf(float3 e) {
	return pow(max((pow(e, 1 / m2) - c1), 0) / (c2 - c3 * pow(e, 1 / m2)), 1 / m1);
}

float3 pq_inv_eotf(float3 y) {
	return pow((c1 + c2 * pow(y, m1)) / (1 + c3 * pow(y, m1)), m2);
}

float3 OrderedDither(float3 rgb, float2 pos) {
	float3 low = floor(rgb * 255) / 255;
	float3 high = low + 1.0 / 255;

	float3 rgb_linear = pow(rgb,)" STRINGIFY(DITHER_GAMMA) R"();
	float3 low_linear = pow(low,)" STRINGIFY(DITHER_GAMMA) R"();
	float3 high_linear = pow(high,)" STRINGIFY(DITHER_GAMMA) R"();

	float noise = noiseTex.Sample(noiseSmp, pos / )" STRINGIFY(NOISE_SIZE) R"().x;
	float3 threshold = lerp(low_linear, high_linear, noise);

	return lerp(low, high, rgb_linear > threshold);
}

VS_OUTPUT VS(VS_INPUT input) {
	VS_OUTPUT output;
	output.pos = float4(input.pos, 0, 1);
	output.tex = input.tex;
	return output;
}

float4 PS(VS_OUTPUT input) : SV_TARGET{
	float3 sample = backBufferTex.Sample(smp, input.tex).rgb;

	if (hdr) {
		float3 hdr10_sample = pq_inv_eotf(saturate(mul(scrgb_to_bt2100, sample)));

		float3 hdr10_res = LutTransformTetrahedral(hdr10_sample);

		float3 scrgb_res = mul(bt2100_to_scrgb, pq_eotf(hdr10_res));

		return float4(scrgb_res, 1);
	}
	else {
		float3 res = LutTransformTetrahedral(sample);

		res = OrderedDither(res, input.pos.xy);

		return float4(res, 1);
	}
}
)";

ID3D11Device* device;
ID3D11DeviceContext* deviceContext;
ID3D11VertexShader* vertexShader;
ID3D11PixelShader* pixelShader;
ID3D11InputLayout* inputLayout;

ID3D11Buffer* vertexBuffer;
UINT numVerts;
UINT stride;
UINT offset;

D3D11_TEXTURE2D_DESC backBufferDesc;
D3D11_TEXTURE2D_DESC textureDesc[2];

ID3D11SamplerState* samplerState;
ID3D11Texture2D* texture[2];
ID3D11ShaderResourceView* textureView[2];

ID3D11SamplerState* noiseSamplerState;
ID3D11ShaderResourceView* noiseTextureView;

ID3D11Buffer* constantBuffer;

struct lutData
{
	int left;
	int top;
	int size;
	bool isHdr;
	ID3D11ShaderResourceView* textureView;
	float* rawLut;
};

void DrawRectangle(struct tagRECT* rect, int index)
{
	float width = backBufferDesc.Width;
	float height = backBufferDesc.Height;

	float screenLeft = rect->left / width;
	float screenTop = rect->top / height;
	float screenRight = rect->right / width;
	float screenBottom = rect->bottom / height;

	float left = screenLeft * 2 - 1;
	float top = screenTop * -2 + 1;
	float right = screenRight * 2 - 1;
	float bottom = screenBottom * -2 + 1;

	width = textureDesc[index].Width;
	height = textureDesc[index].Height;
	float texLeft = rect->left / width;
	float texTop = rect->top / height;
	float texRight = rect->right / width;
	float texBottom = rect->bottom / height;

	float vertexData[] = {
		left, bottom, texLeft, texBottom,
		left, top, texLeft, texTop,
		right, bottom, texRight, texBottom,
		right, top, texRight, texTop
	};

	D3D11_MAPPED_SUBRESOURCE resource;
	EXECUTE_WITH_LOG(deviceContext->Map(vertexBuffer, 0, D3D11_MAP_WRITE_DISCARD, 0, &resource))
	memcpy(resource.pData, vertexData, stride * numVerts);
	deviceContext->Unmap(vertexBuffer, 0);

	deviceContext->IASetVertexBuffers(0, 1, &vertexBuffer, &stride, &offset);

	deviceContext->Draw(numVerts, 0);
}

int numLuts;

lutData* luts;

bool ParseLUT(lutData* lut, char* filename)
{
	FILE* file = fopen(filename, "r");
	if (file == NULL) return false;

	char line[256];
	unsigned int lutSize;

	while (1)
	{
		if (!fgets(line, sizeof(line), file))
		{
			fclose(file);
			return false;
		}
		if (sscanf(line, "LUT_3D_SIZE%d", &lutSize) == 1)
		{
			break;
		}
	}
	// borgaccio
	float* rawLut = (float*)malloc(lutSize * lutSize * lutSize * 4 * sizeof(float));
	// lut_3d_vec rawLut(lutSize, { lutSize, {lutSize, RGBA_VEC} });

	for (int b = 0; b < lutSize; b++)
	{
		for (int g = 0; g < lutSize; g++)
		{
			for (int r = 0; r < lutSize; r++)
			{
				while (1)
				{
					if (!fgets(line, sizeof(line), file))
					{
						fclose(file);
						// free(rawLut);
						return false;
					}
					if (line[0] <= '9' && line[0] != '#' && line[0] != '\n')
					{
						float red, green, blue;

						if (sscanf(line, "%f%f%f", &red, &green, &blue) != 3)
						{
							fclose(file);
							// free(rawLut);
							return false;
						}
						LUT_ACCESS_INDEX(rawLut, b, g, r, 0, lutSize) = red;
						LUT_ACCESS_INDEX(rawLut, b, g, r, 1, lutSize) = green;
						LUT_ACCESS_INDEX(rawLut, b, g, r, 2, lutSize) = blue;
						LUT_ACCESS_INDEX(rawLut, b, g, r, 3, lutSize) = 1;

						break;
					}
				}
			}
		}
	}
	fclose(file);
	lut->size = lutSize;
	lut->rawLut = rawLut;
	return true;
}

bool AddLUTs(char* folder)
{
	WIN32_FIND_DATAA findData;

	char path[MAX_PATH];
	strcpy(path, folder);
	strcat(path, "\\*");
	HANDLE hFind = FindFirstFileA(path, &findData);
	if (hFind == INVALID_HANDLE_VALUE) return false;
	do
	{
		if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			char filePath[MAX_PATH];
			char* fileName = findData.cFileName;

			strcpy(filePath, folder);
			strcat(filePath, "\\");
			strcat(filePath, fileName);

			luts = (lutData*)RESIZE(luts, numLuts + 1)
			lutData* lut = &luts[numLuts];
			if (sscanf(findData.cFileName, "%d_%d", &lut->left, &lut->top) == 2)
			{
				lut->isHdr = strstr(fileName, "hdr") != NULL;
				lut->textureView = NULL;
				if (!ParseLUT(lut, filePath))
				{
					// TODO: Remove this debug instruction
					MESSAGE_BOX_DBG("LUT could not be parsed", MB_OK | MB_ICONWARNING)
					FindClose(hFind);
					return false;
				}
				numLuts++;
			}
		}
	}
	while (FindNextFileA(hFind, &findData) != 0);
	FindClose(hFind);
	return true;
}

int numLutTargets;
void** lutTargets;

bool IsLUTActive(void* target)
{
	for (int i = 0; i < numLutTargets; i++)
	{
		if (lutTargets[i] == target)
		{
			return true;
		}
	}
	return false;
}

void SetLUTActive(void* target)
{
	if (!IsLUTActive(target))
	{
		lutTargets = (void**)RESIZE(lutTargets, numLutTargets + 1)
		lutTargets[numLutTargets++] = target;
	}
}

void UnsetLUTActive(void* target)
{
	for (int i = 0; i < numLutTargets; i++)
	{
		if (lutTargets[i] == target)
		{
			lutTargets[i] = lutTargets[--numLutTargets];
			lutTargets = (void**)RESIZE(lutTargets, numLutTargets)
			return;
		}
	}
}

// Diagnostic for LUT matching
static bool lut_match_diag_logged = false;

lutData* GetLUTDataFromCOverlayContext(void* context, bool hdr)
{
	int left, top;
	if (isWindows11)
	{
		float* rect = (float*)((unsigned char*)*(void**)context + COverlayContext_DeviceClipBox_offset_w11);
		left = (int)rect[0];
		top = (int)rect[1];

		// Log once for diagnostics
		if (!lut_match_diag_logged)
		{
			lut_match_diag_logged = true;
			std::stringstream ss;
			ss << "=== LUT Matching Diagnostics ===" << std::endl;
			ss << "  context ptr: 0x" << std::hex << (UINT_PTR)context << std::endl;
			ss << "  *context (deref): 0x" << std::hex << (UINT_PTR)*(void**)context << std::endl;
			ss << "  DeviceClipBox offset: 0x" << std::hex << COverlayContext_DeviceClipBox_offset_w11 << std::endl;
			ss << "  rect ptr: 0x" << std::hex << (UINT_PTR)rect << std::endl;
			ss << "  Detected position: left=" << std::dec << left << ", top=" << top << std::endl;
			ss << "  Looking for LUT with hdr=" << (hdr ? "true" : "false") << std::endl;
			ss << "  Available LUTs (" << numLuts << "):";
			diag_log(ss.str().c_str());
			for (int i = 0; i < numLuts; i++)
			{
				std::stringstream lutss;
				lutss << "    LUT[" << i << "]: left=" << luts[i].left << ", top=" << luts[i].top << ", hdr=" << (luts[i].isHdr ? "true" : "false");
				diag_log(lutss.str().c_str());
			}
		}
	}
	else
	{
		int* rect = (int*)((unsigned char*)context + COverlayContext_DeviceClipBox_offset);
		left = rect[0];
		top = rect[1];
	}

	for (int i = 0; i < numLuts; i++)
	{
		if (luts[i].left == left && luts[i].top == top && luts[i].isHdr == hdr)
		{
			return &luts[i];
		}
	}
	return NULL;
}

void InitializeStuff(IDXGISwapChain* swapChain)
{
	try
	{
		EXECUTE_WITH_LOG(swapChain->GetDevice(IID_ID3D11Device, (void**)&device))
		LOG_ADDRESS("Current swapchain address is: ", swapChain)
		LOG_ONLY_ONCE("Device successfully gathered")
		LOG_ADDRESS("The device address is: ", device)

		device->GetImmediateContext(&deviceContext);
		LOG_ONLY_ONCE("Got context after device")
		LOG_ADDRESS("The Device context is located at address: ", deviceContext)
		{
			ID3DBlob* vsBlob;
			ID3DBlob* compile_error_interface;
			LOG_ONLY_ONCE(("Trying to compile vshader with this code:\n" + std::string(shaders)).c_str())
			EXECUTE_D3DCOMPILE_WITH_LOG(
				D3DCompile(shaders, sizeof shaders, NULL, NULL, NULL, "VS", "vs_5_0", 0, 0, &vsBlob, &
					compile_error_interface), compile_error_interface)


			LOG_ONLY_ONCE("Vertex shader compiled successfully")
			EXECUTE_WITH_LOG(device->CreateVertexShader(vsBlob->GetBufferPointer(),
				vsBlob->GetBufferSize(), NULL, &vertexShader))


			LOG_ONLY_ONCE("Vertex shader created successfully")
			D3D11_INPUT_ELEMENT_DESC inputElementDesc[] =
			{
				{"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
				{
					"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, D3D11_APPEND_ALIGNED_ELEMENT,
					D3D11_INPUT_PER_VERTEX_DATA, 0
				}
			};
			EXECUTE_WITH_LOG(device->CreateInputLayout(inputElementDesc, ARRAYSIZE(inputElementDesc),
				vsBlob->GetBufferPointer(),
				vsBlob->GetBufferSize(), &inputLayout))

			vsBlob->Release();
		}
		{
			ID3DBlob* psBlob;
			ID3DBlob* compile_error_interface;
			EXECUTE_D3DCOMPILE_WITH_LOG(
				D3DCompile(shaders, sizeof shaders, NULL, NULL, NULL, "PS", "ps_5_0", 0, 0, &psBlob, &
					compile_error_interface), compile_error_interface)

			LOG_ONLY_ONCE("Pixel shader compiled successfully")
			device->CreatePixelShader(psBlob->GetBufferPointer(),
			                          psBlob->GetBufferSize(), NULL, &pixelShader);
			psBlob->Release();
		}
		{
			stride = 4 * sizeof(float);
			numVerts = 4;
			offset = 0;

			D3D11_BUFFER_DESC vertexBufferDesc = {};
			vertexBufferDesc.ByteWidth = stride * numVerts;
			vertexBufferDesc.Usage = D3D11_USAGE_DYNAMIC;
			vertexBufferDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
			vertexBufferDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

			EXECUTE_WITH_LOG(device->CreateBuffer(&vertexBufferDesc, NULL, &vertexBuffer))
		}
		{
			D3D11_SAMPLER_DESC samplerDesc = {};
			samplerDesc.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
			samplerDesc.AddressU = samplerDesc.AddressV = samplerDesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
			samplerDesc.ComparisonFunc = D3D11_COMPARISON_NEVER;

			EXECUTE_WITH_LOG(device->CreateSamplerState(&samplerDesc, &samplerState))
		}
		for (int i = 0; i < numLuts; i++)
		{
			lutData* lut = &luts[i];

			D3D11_TEXTURE3D_DESC desc = {};
			desc.Width = lut->size;
			desc.Height = lut->size;
			desc.Depth = lut->size;
			desc.MipLevels = 1;
			desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
			desc.Usage = D3D11_USAGE_IMMUTABLE;
			desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

			D3D11_SUBRESOURCE_DATA initData;
			initData.pSysMem = lut->rawLut;
			initData.SysMemPitch = lut->size * 4 * sizeof(float);
			initData.SysMemSlicePitch = lut->size * lut->size * 4 * sizeof(float);

			ID3D11Texture3D* tex;
			EXECUTE_WITH_LOG(device->CreateTexture3D(&desc, &initData, &tex))
			EXECUTE_WITH_LOG(device->CreateShaderResourceView((ID3D11Resource*)tex, NULL, &luts[i].textureView))
			tex->Release();
			free(lut->rawLut);
			lut->rawLut = NULL;
		}
		{
			D3D11_SAMPLER_DESC samplerDesc = {};
			samplerDesc.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
			samplerDesc.AddressU = samplerDesc.AddressV = samplerDesc.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
			samplerDesc.ComparisonFunc = D3D11_COMPARISON_NEVER;

			EXECUTE_WITH_LOG(device->CreateSamplerState(&samplerDesc, &noiseSamplerState))
		}
		{
			D3D11_TEXTURE2D_DESC desc = {};
			desc.Width = NOISE_SIZE;
			desc.Height = NOISE_SIZE;
			desc.MipLevels = 1;
			desc.ArraySize = 1;
			desc.Format = DXGI_FORMAT_R32_FLOAT;
			desc.SampleDesc.Count = 1;
			desc.SampleDesc.Quality = 0;
			desc.Usage = D3D11_USAGE_IMMUTABLE;
			desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

			float noise[NOISE_SIZE][NOISE_SIZE];

			for (int i = 0; i < NOISE_SIZE; i++)
			{
				for (int j = 0; j < NOISE_SIZE; j++)
				{
					noise[i][j] = (noiseBytes[i][j] + 0.5) / 256;
				}
			}

			D3D11_SUBRESOURCE_DATA initData;
			initData.pSysMem = noise;
			initData.SysMemPitch = sizeof(noise[0]);

			ID3D11Texture2D* tex;
			EXECUTE_WITH_LOG(device->CreateTexture2D(&desc, &initData, &tex))
			EXECUTE_WITH_LOG(device->CreateShaderResourceView((ID3D11Resource*)tex, NULL, &noiseTextureView))
			tex->Release();
		}
		{
			D3D11_BUFFER_DESC constantBufferDesc = {};
			constantBufferDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
			constantBufferDesc.ByteWidth = 16;
			constantBufferDesc.Usage = D3D11_USAGE_DYNAMIC;
			constantBufferDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

			EXECUTE_WITH_LOG(device->CreateBuffer(&constantBufferDesc, NULL, &constantBuffer))
			LOG_ONLY_ONCE("Final buffer created in InitializeStuff")
		}
	}
	catch (std::exception& ex)
	{
		std::stringstream ex_message;
		ex_message << "Exception caught at line " << __LINE__ << ": " << ex.what() << std::endl;
		LOG_ONLY_ONCE(ex_message.str().c_str())
		throw;
	}
	catch (...)
	{
		std::stringstream ex_message;
		ex_message << "Exception caught at line " << __LINE__ << ": " << std::endl;
		LOG_ONLY_ONCE(ex_message.str().c_str())
		throw;
	}
}

void UninitializeStuff()
{
	RELEASE_IF_NOT_NULL(device)
	RELEASE_IF_NOT_NULL(deviceContext)
	RELEASE_IF_NOT_NULL(vertexShader)
	RELEASE_IF_NOT_NULL(pixelShader)
	RELEASE_IF_NOT_NULL(inputLayout)
	RELEASE_IF_NOT_NULL(vertexBuffer)
	RELEASE_IF_NOT_NULL(samplerState)
	for (int i = 0; i < 2; i++)
	{
		RELEASE_IF_NOT_NULL(texture[i])
		RELEASE_IF_NOT_NULL(textureView[i])
	}
	RELEASE_IF_NOT_NULL(noiseSamplerState)
	RELEASE_IF_NOT_NULL(noiseTextureView)
	RELEASE_IF_NOT_NULL(constantBuffer)
	for (int i = 0; i < numLuts; i++)
	{
		free(luts[i].rawLut);
		RELEASE_IF_NOT_NULL(luts[i].textureView)
	}
	free(luts);
	free(lutTargets);
}

bool ApplyLUT(void* cOverlayContext, IDXGISwapChain* swapChain, struct tagRECT* rects, int numRects)
{
	try
	{
		if (!device)
		{
			LOG_ONLY_ONCE("Initializing stuff in ApplyLUT")
			InitializeStuff(swapChain);
		}
		LOG_ONLY_ONCE("Init done, continuing with LUT application")

		ID3D11Texture2D* backBuffer;
		ID3D11RenderTargetView* renderTargetView;


		EXECUTE_WITH_LOG(swapChain->GetBuffer(0, IID_ID3D11Texture2D, (void**)&backBuffer))

		D3D11_TEXTURE2D_DESC newBackBufferDesc;
		backBuffer->GetDesc(&newBackBufferDesc);

		int index = -1;
		if (newBackBufferDesc.Format == DXGI_FORMAT_B8G8R8A8_UNORM)
		{
			index = 0;
		}
		else if (newBackBufferDesc.Format == DXGI_FORMAT_R16G16B16A16_FLOAT)
		{
			index = 1;
		}

		lutData* lut;
		if (index == -1 || !(lut = GetLUTDataFromCOverlayContext(cOverlayContext, index == 1)))
		{
			backBuffer->Release();
			return false;
		}

		D3D11_TEXTURE2D_DESC oldTextureDesc = textureDesc[index];
		if (newBackBufferDesc.Width > oldTextureDesc.Width || newBackBufferDesc.Height > oldTextureDesc.Height)
		{
			if (texture[index] != NULL)
			{
				texture[index]->Release();
				textureView[index]->Release();
			}

			UINT newWidth = max(newBackBufferDesc.Width, oldTextureDesc.Width);
			UINT newHeight = max(newBackBufferDesc.Height, oldTextureDesc.Height);

			D3D11_TEXTURE2D_DESC newTextureDesc;

			newTextureDesc = newBackBufferDesc;
			newTextureDesc.Width = newWidth;
			newTextureDesc.Height = newHeight;
			newTextureDesc.Usage = D3D11_USAGE_DEFAULT;
			newTextureDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
			newTextureDesc.CPUAccessFlags = 0;
			newTextureDesc.MiscFlags = 0;

			textureDesc[index] = newTextureDesc;

			EXECUTE_WITH_LOG(device->CreateTexture2D(&textureDesc[index], NULL, &texture[index]))
			EXECUTE_WITH_LOG(
				device->CreateShaderResourceView((ID3D11Resource*)texture[index], NULL, &textureView[index]))
		}

		backBufferDesc = newBackBufferDesc;

		EXECUTE_WITH_LOG(device->CreateRenderTargetView((ID3D11Resource*)backBuffer, NULL, &renderTargetView))
		const D3D11_VIEWPORT d3d11_viewport(0, 0, backBufferDesc.Width, backBufferDesc.Height, 0.0f, 1.0f);
		deviceContext->RSSetViewports(1, &d3d11_viewport);

		deviceContext->OMSetRenderTargets(1, &renderTargetView, NULL);
		renderTargetView->Release();

		deviceContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
		deviceContext->IASetInputLayout(inputLayout);

		deviceContext->VSSetShader(vertexShader, NULL, 0);
		deviceContext->PSSetShader(pixelShader, NULL, 0);

		deviceContext->PSSetShaderResources(0, 1, &textureView[index]);
		deviceContext->PSSetShaderResources(1, 1, &lut->textureView);
		deviceContext->PSSetSamplers(0, 1, &samplerState);

		deviceContext->PSSetShaderResources(2, 1, &noiseTextureView);
		deviceContext->PSSetSamplers(1, 1, &noiseSamplerState);

		int constantData[4] = {lut->size, index == 1};

		D3D11_MAPPED_SUBRESOURCE resource;
		EXECUTE_WITH_LOG(deviceContext->Map((ID3D11Resource*)constantBuffer, 0, D3D11_MAP_WRITE_DISCARD, 0,
			&resource))
		memcpy(resource.pData, constantData, sizeof(constantData));
		deviceContext->Unmap((ID3D11Resource*)constantBuffer, 0);

		deviceContext->PSSetConstantBuffers(0, 1, &constantBuffer);

		for (int i = 0; i < numRects; i++)
		{
			D3D11_BOX sourceRegion;
			sourceRegion.left = rects[i].left;
			sourceRegion.right = rects[i].right;
			sourceRegion.top = rects[i].top;
			sourceRegion.bottom = rects[i].bottom;
			sourceRegion.front = 0;
			sourceRegion.back = 1;

			deviceContext->CopySubresourceRegion((ID3D11Resource*)texture[index], 0, rects[i].left,
			                                     rects[i].top, 0, (ID3D11Resource*)backBuffer, 0, &sourceRegion);
			DrawRectangle(&rects[i], index);
		}

		backBuffer->Release();
		return true;
	}
	catch (std::exception& ex)
	{
		std::stringstream ex_message;
		ex_message << "Exception caught at line " << __LINE__ << ": " << ex.what() << std::endl;
		LOG_ONLY_ONCE(ex_message.str().c_str())
		return false;
	}
	catch (...)
	{
		std::stringstream ex_message;
		ex_message << "Exception caught at line " << __LINE__ << std::endl;
		LOG_ONLY_ONCE(ex_message.str().c_str())
		return false;
	}
}

typedef struct rectVec
{
	struct tagRECT* start;
	struct tagRECT* end;
	struct tagRECT* cap;
} rectVec;

typedef long (COverlayContext_Present_t)(void*, void*, unsigned int, rectVec*, unsigned int, bool);

COverlayContext_Present_t* COverlayContext_Present_orig;
COverlayContext_Present_t* COverlayContext_Present_real_orig;


// Runtime diagnostic counters
static int hook_call_count = 0;
static int hook_passed_retaddr_check = 0;
static int hook_hw_protected = 0;
static int hook_lut_applied = 0;
static int hook_lut_failed = 0;
static bool runtime_diag_logged = false;

long COverlayContext_Present_hook(void* self, void* overlaySwapChain, unsigned int a3, rectVec* rectVec,
                                  unsigned int a5, bool a6)
{
	hook_call_count++;

	// Log runtime diagnostics once after some calls
	if (!runtime_diag_logged && hook_call_count >= 100)
	{
		runtime_diag_logged = true;
		std::stringstream ss;
		ss << "=== Runtime Hook Diagnostics (after " << hook_call_count << " calls) ===";
		diag_log(ss.str().c_str());
		ss.str("");
		ss << "  RetAddr check passed: " << hook_passed_retaddr_check;
		diag_log(ss.str().c_str());
		ss.str("");
		ss << "  HW Protected (skipped): " << hook_hw_protected;
		diag_log(ss.str().c_str());
		ss.str("");
		ss << "  LUT applied: " << hook_lut_applied;
		diag_log(ss.str().c_str());
		ss.str("");
		ss << "  LUT failed: " << hook_lut_failed;
		diag_log(ss.str().c_str());
	}

	if (_ReturnAddress() < (void*)COverlayContext_Present_real_orig)
	{
		hook_passed_retaddr_check++;
		LOG_ONLY_ONCE("I am inside COverlayContext::Present hook inside the main if condition")

		int hardwareProtectedOffset = IOverlaySwapChain_HardwareProtected_offset;
		if (isWindows11)
		{
			if (isWindows11_25H2)
				hardwareProtectedOffset = IOverlaySwapChain_HardwareProtected_offset_w11_25H2;
			else if (isWindows11_24H2)
				hardwareProtectedOffset = IOverlaySwapChain_HardwareProtected_offset_w11_24H2;
			else
				hardwareProtectedOffset = IOverlaySwapChain_HardwareProtected_offset_w11;
		}

		if (*((bool*)overlaySwapChain + hardwareProtectedOffset))
		{
			hook_hw_protected++;
			std::stringstream hw_protection_message;
			hw_protection_message << "I'm inside the Hardware protection condition - 0x" << std::hex << (bool*)
				overlaySwapChain + hardwareProtectedOffset << " - value: 0x" << *((bool*)
					overlaySwapChain + hardwareProtectedOffset);
			LOG_ONLY_ONCE(hw_protection_message.str().c_str())
			UnsetLUTActive(self);
		}
		else
		{
			std::stringstream hw_protection_message;
			hw_protection_message << "I'm outside the Hardware protection condition - 0x" << std::hex << (bool*)
				overlaySwapChain + hardwareProtectedOffset << " - value: 0x" << *((bool*)
					overlaySwapChain + hardwareProtectedOffset);
			LOG_ONLY_ONCE(hw_protection_message.str().c_str())

			IDXGISwapChain* swapChain;
			if (isWindows11)
			{
				LOG_ONLY_ONCE("Gathering IDXGISwapChain pointer")
				int sub_from_legacy_swapchain = *(int*)((unsigned char*)overlaySwapChain - 4);
				void* real_overlay_swap_chain = (unsigned char*)overlaySwapChain - sub_from_legacy_swapchain -
					0x1b0;
				int idxgiSwapChainOffset;
				if (isWindows11_25H2)
					idxgiSwapChainOffset = IOverlaySwapChain_IDXGISwapChain_offset_w11_25H2;
				else if (isWindows11_24H2)
					idxgiSwapChainOffset = IOverlaySwapChain_IDXGISwapChain_offset_w11_24H2;
				else
					idxgiSwapChainOffset = IOverlaySwapChain_IDXGISwapChain_offset_w11;
				swapChain = *(IDXGISwapChain**)((unsigned char*)real_overlay_swap_chain +
					idxgiSwapChainOffset);
			}
			else
			{
				swapChain = *(IDXGISwapChain**)((unsigned char*)overlaySwapChain +
					IOverlaySwapChain_IDXGISwapChain_offset);
			}

			if (ApplyLUT(self, swapChain, rectVec->start, rectVec->end - rectVec->start))
			{
				hook_lut_applied++;
				LOG_ONLY_ONCE("Setting LUTactive")
				SetLUTActive(self);
			}
			else
			{
				hook_lut_failed++;
				LOG_ONLY_ONCE("Un-setting LUTactive")
				UnsetLUTActive(self);
			}
		}
	}

	return COverlayContext_Present_orig(self, overlaySwapChain, a3, rectVec, a5, a6);
}

typedef bool (COverlayContext_IsCandidateDirectFlipCompatbile_t)(void*, void*, void*, void*, int, unsigned int, bool,
                                                                 bool);

COverlayContext_IsCandidateDirectFlipCompatbile_t* COverlayContext_IsCandidateDirectFlipCompatbile_orig;

bool COverlayContext_IsCandidateDirectFlipCompatbile_hook(void* self, void* a2, void* a3, void* a4, int a5,
                                                          unsigned int a6, bool a7, bool a8)
{
	if (IsLUTActive(self))
	{
		return false;
	}
	return COverlayContext_IsCandidateDirectFlipCompatbile_orig(self, a2, a3, a4, a5, a6, a7, a8);
}

typedef bool (COverlayContext_OverlaysEnabled_t)(void*);

COverlayContext_OverlaysEnabled_t* COverlayContext_OverlaysEnabled_orig;

bool COverlayContext_OverlaysEnabled_hook(void* self)
{
	if (IsLUTActive(self))
	{
		LOG_ONLY_ONCE("LUT ACTIVE FALSE in overlaysEnabled")
		return false;
	}
	return COverlayContext_OverlaysEnabled_orig(self);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		{
			DIAG_LOG("=== DWM LUT DLL Attached ===");

			HMODULE dwmcore = GetModuleHandle(L"dwmcore.dll");
			MODULEINFO moduleInfo;
			GetModuleInformation(GetCurrentProcess(), dwmcore, &moduleInfo, sizeof moduleInfo);

			{
				std::stringstream ss;
				ss << "dwmcore.dll base: 0x" << std::hex << (UINT_PTR)dwmcore << " size: " << std::dec << moduleInfo.SizeOfImage;
				DIAG_LOG(ss.str().c_str());
			}

			OSVERSIONINFOEX versionInfo;
			ZeroMemory(&versionInfo, sizeof OSVERSIONINFOEX);
			versionInfo.dwOSVersionInfoSize = sizeof OSVERSIONINFOEX;
			versionInfo.dwBuildNumber = 22000;

			ULONGLONG dwlConditionMask = 0;
			VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

			if (VerifyVersionInfo(&versionInfo, VER_BUILDNUMBER, dwlConditionMask))
			{
				isWindows11 = true;

				// Check for Windows 11 25H2 (Build 26200+) first
				versionInfo.dwBuildNumber = 26200;
				dwlConditionMask = 0;
				VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

				if (VerifyVersionInfo(&versionInfo, VER_BUILDNUMBER, dwlConditionMask))
				{
					isWindows11_25H2 = true;
					isWindows11_24H2 = true; // 25H2 implies 24H2+
					DIAG_LOG("Detected Windows 11 25H2+ (Build >= 26200)");
				}
				else
				{
					isWindows11_25H2 = false;

					// Check for Windows 11 24H2 (Build 26100+)
					versionInfo.dwBuildNumber = 26100;
					dwlConditionMask = 0;
					VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

					if (VerifyVersionInfo(&versionInfo, VER_BUILDNUMBER, dwlConditionMask))
					{
						isWindows11_24H2 = true;
						DIAG_LOG("Detected Windows 11 24H2 (Build >= 26100, < 26200)");
					}
					else
					{
						isWindows11_24H2 = false;
						DIAG_LOG("Detected Windows 11 (Build < 26100)");
					}
				}
			}
			else
			{
				isWindows11 = false;
				isWindows11_24H2 = false;
				isWindows11_25H2 = false;
				DIAG_LOG("Detected Windows 10");
			}

			// TODO: Remove this debug instruction
			MESSAGE_BOX_DBG("DWM LUT ATTACH", MB_OK)

			if (isWindows11)
			{
				// TODO: Remove this debug instruction
				MESSAGE_BOX_DBG("DETECTED WINDOWS 11 OS", MB_OK)

				// Select patterns based on Windows version
				const unsigned char* presentPattern;
				const unsigned char* directFlipPattern;
				const unsigned char* overlaysEnabledPattern;
				size_t presentPatternSize;
				size_t directFlipPatternSize;
				size_t overlaysEnabledPatternSize;

				if (isWindows11_25H2)
				{
					presentPattern = COverlayContext_Present_bytes_w11_25H2;
					directFlipPattern = COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11_25H2;
					overlaysEnabledPattern = COverlayContext_OverlaysEnabled_bytes_w11_25H2;
					presentPatternSize = sizeof COverlayContext_Present_bytes_w11_25H2;
					directFlipPatternSize = sizeof COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11_25H2;
					overlaysEnabledPatternSize = sizeof COverlayContext_OverlaysEnabled_bytes_w11_25H2;
					DIAG_LOG("Using Windows 11 25H2 patterns");
				}
				else if (isWindows11_24H2)
				{
					presentPattern = COverlayContext_Present_bytes_w11_24H2;
					directFlipPattern = COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11_24H2;
					overlaysEnabledPattern = COverlayContext_OverlaysEnabled_bytes_w11_24H2;
					presentPatternSize = sizeof COverlayContext_Present_bytes_w11_24H2;
					directFlipPatternSize = sizeof COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11_24H2;
					overlaysEnabledPatternSize = sizeof COverlayContext_OverlaysEnabled_bytes_w11_24H2;
					DIAG_LOG("Using Windows 11 24H2 patterns");
				}
				else
				{
					presentPattern = COverlayContext_Present_bytes_w11;
					directFlipPattern = COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11;
					overlaysEnabledPattern = COverlayContext_OverlaysEnabled_bytes_w11;
					presentPatternSize = sizeof COverlayContext_Present_bytes_w11;
					directFlipPatternSize = sizeof COverlayContext_IsCandidateDirectFlipCompatbile_bytes_w11;
					overlaysEnabledPatternSize = sizeof COverlayContext_OverlaysEnabled_bytes_w11;
					DIAG_LOG("Using Windows 11 (pre-24H2) patterns");
				}

				DIAG_LOG_BYTES("Searching for Present pattern: ", presentPattern, presentPatternSize);
				DIAG_LOG_BYTES("Searching for DirectFlip pattern: ", directFlipPattern, directFlipPatternSize);
				DIAG_LOG_BYTES("Searching for OverlaysEnabled pattern: ", overlaysEnabledPattern, overlaysEnabledPatternSize);

				for (size_t i = 0; i <= moduleInfo.SizeOfImage - overlaysEnabledPatternSize; i++)
				{
					unsigned char* address = (unsigned char*)dwmcore + i;
					if (!COverlayContext_Present_orig && presentPatternSize <= moduleInfo.
						SizeOfImage - i && !aob_match_inverse(address, presentPattern,
						                                      presentPatternSize))
					{
						// TODO: Remove this debug instruction
						MESSAGE_BOX_DBG("DETECTED COverlayContextPresent address", MB_OK)

						COverlayContext_Present_orig = (COverlayContext_Present_t*)address;
						COverlayContext_Present_real_orig = COverlayContext_Present_orig;

						std::stringstream ss;
						ss << "Found COverlayContext::Present at offset 0x" << std::hex << i;
						DIAG_LOG(ss.str().c_str());
						DIAG_LOG_BYTES("  Bytes at location: ", address, 32);
					}
					else if (!COverlayContext_IsCandidateDirectFlipCompatbile_orig && directFlipPatternSize
						<= moduleInfo.SizeOfImage - i && !
						aob_match_inverse(
							address, directFlipPattern,
							directFlipPatternSize))
					{
						COverlayContext_IsCandidateDirectFlipCompatbile_orig = (
							COverlayContext_IsCandidateDirectFlipCompatbile_t*)address;

						std::stringstream ss;
						ss << "Found COverlayContext::IsCandidateDirectFlipCompatbile at offset 0x" << std::hex << i;
						DIAG_LOG(ss.str().c_str());
						DIAG_LOG_BYTES("  Bytes at location: ", address, 32);
					}
					else if (!COverlayContext_OverlaysEnabled_orig && overlaysEnabledPatternSize
						<= moduleInfo.SizeOfImage - i && !aob_match_inverse(
							address, overlaysEnabledPattern,
							overlaysEnabledPatternSize))
					{
						COverlayContext_OverlaysEnabled_orig = (COverlayContext_OverlaysEnabled_t*)address;

						std::stringstream ss;
						ss << "Found COverlayContext::OverlaysEnabled at offset 0x" << std::hex << i;
						DIAG_LOG(ss.str().c_str());
						DIAG_LOG_BYTES("  Bytes at location: ", address, 32);
					}
					if (COverlayContext_Present_orig && COverlayContext_IsCandidateDirectFlipCompatbile_orig &&
						COverlayContext_OverlaysEnabled_orig)
					{
						MESSAGE_BOX_DBG("All addresses successfully retrieved", MB_OK)
						DIAG_LOG("All function addresses found successfully!");

						break;
					}
				}

				// Log what was NOT found
				if (!COverlayContext_Present_orig)
				{
					DIAG_LOG("ERROR: COverlayContext::Present pattern NOT FOUND!");
				}
				if (!COverlayContext_IsCandidateDirectFlipCompatbile_orig)
				{
					DIAG_LOG("ERROR: COverlayContext::IsCandidateDirectFlipCompatbile pattern NOT FOUND!");
				}
				if (!COverlayContext_OverlaysEnabled_orig)
				{
					DIAG_LOG("ERROR: COverlayContext::OverlaysEnabled pattern NOT FOUND!");
				}

				// If any pattern was not found, run pattern discovery to find candidates
				if (!COverlayContext_Present_orig || !COverlayContext_IsCandidateDirectFlipCompatbile_orig || !COverlayContext_OverlaysEnabled_orig)
				{
					DIAG_LOG("Running pattern discovery to find potential matches...");
					DISCOVER_PATTERNS((unsigned char*)dwmcore, moduleInfo.SizeOfImage);
				}

				DWORD rev;
				DWORD revSize = sizeof(rev);
				RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "UBR", RRF_RT_DWORD,
				             NULL, &rev, &revSize);

				{
					std::stringstream ss;
					ss << "Windows revision (UBR): " << rev;
					DIAG_LOG(ss.str().c_str());
				}

				if (isWindows11_25H2)
				{
					MESSAGE_BOX_DBG("Detected Windows 11 25H2", MB_OK)

					// Use 25H2 specific offsets
					COverlayContext_DeviceClipBox_offset_w11 = COverlayContext_DeviceClipBox_offset_w11_25H2;
					// Note: HardwareProtected_offset is handled separately in the hooking code
				}
				else if (isWindows11_24H2)
				{
					MESSAGE_BOX_DBG("Detected Windows 11 24H2", MB_OK)

					// Use 24H2 specific offsets
					COverlayContext_DeviceClipBox_offset_w11 = COverlayContext_DeviceClipBox_offset_w11_24H2;
					// Note: HardwareProtected_offset is handled separately in the hooking code
				}
				else if (rev >= 706)
				{
					MESSAGE_BOX_DBG("Detected recent Windows OS", MB_OK)

					// COverlayContext_DeviceClipBox_offset_w11 += 8;
				}
			}
			else
			{
				for (size_t i = 0; i <= moduleInfo.SizeOfImage - sizeof(COverlayContext_Present_bytes); i++)
				{
					unsigned char* address = (unsigned char*)dwmcore + i;
					if (!COverlayContext_Present_orig && !memcmp(address, COverlayContext_Present_bytes,
					                                             sizeof(COverlayContext_Present_bytes)))
					{
						COverlayContext_Present_orig = (COverlayContext_Present_t*)address;
						COverlayContext_Present_real_orig = COverlayContext_Present_orig;
					}
					else if (!COverlayContext_IsCandidateDirectFlipCompatbile_orig && !memcmp(
						address, COverlayContext_IsCandidateDirectFlipCompatbile_bytes,
						sizeof(COverlayContext_IsCandidateDirectFlipCompatbile_bytes)))
					{
						static int found = 0;
						found++;
						if (found == 2)
						{
							COverlayContext_IsCandidateDirectFlipCompatbile_orig = (
								COverlayContext_IsCandidateDirectFlipCompatbile_t*)(address - 0xa);
						}
					}
					else if (!COverlayContext_OverlaysEnabled_orig && !memcmp(
						address, COverlayContext_OverlaysEnabled_bytes, sizeof(COverlayContext_OverlaysEnabled_bytes)))
					{
						COverlayContext_OverlaysEnabled_orig = (COverlayContext_OverlaysEnabled_t*)(address - 0x7);
					}
					if (COverlayContext_Present_orig && COverlayContext_IsCandidateDirectFlipCompatbile_orig &&
						COverlayContext_OverlaysEnabled_orig)
					{
						break;
					}
				}
			}

			char lutFolderPath[MAX_PATH];
			ExpandEnvironmentStringsA(LUT_FOLDER, lutFolderPath, sizeof(lutFolderPath));

			{
				std::stringstream ss;
				ss << "Looking for LUTs in: " << lutFolderPath;
				DIAG_LOG(ss.str().c_str());
			}

			if (!AddLUTs(lutFolderPath))
			{
				DIAG_LOG("ERROR: Failed to load LUTs - returning FALSE");
				return FALSE;
			}

			{
				std::stringstream ss;
				ss << "Loaded " << numLuts << " LUT(s)";
				DIAG_LOG(ss.str().c_str());
			}

			char variable_message_states[300];
			sprintf(variable_message_states, "Current variable states: COverlayContext::Present - %p\t"
			        "COverlayContext::IsCandidateDirectFlipCompatible - %p\tCOverlayContext::OverlaysEnabled - %p",
			        COverlayContext_Present_orig,
			        COverlayContext_IsCandidateDirectFlipCompatbile_orig, COverlayContext_OverlaysEnabled_orig);

			MESSAGE_BOX_DBG(variable_message_states, MB_OK)
			DIAG_LOG(variable_message_states);

			if (COverlayContext_Present_orig && COverlayContext_IsCandidateDirectFlipCompatbile_orig &&
				COverlayContext_OverlaysEnabled_orig && numLuts != 0)

			{
				MH_Initialize();
				MH_CreateHook((PVOID)COverlayContext_Present_orig, (PVOID)COverlayContext_Present_hook,
				              (PVOID*)&COverlayContext_Present_orig);
				MH_CreateHook((PVOID)COverlayContext_IsCandidateDirectFlipCompatbile_orig,
				              (PVOID)COverlayContext_IsCandidateDirectFlipCompatbile_hook,
				              (PVOID*)&COverlayContext_IsCandidateDirectFlipCompatbile_orig);
				MH_CreateHook((PVOID)COverlayContext_OverlaysEnabled_orig, (PVOID)COverlayContext_OverlaysEnabled_hook,
				              (PVOID*)&COverlayContext_OverlaysEnabled_orig);
				MH_EnableHook(MH_ALL_HOOKS);
				LOG_ONLY_ONCE("DWM HOOK DLL INITIALIZATION. START LOGGING")
				MESSAGE_BOX_DBG("DWM HOOK INITIALIZATION", MB_OK)
				DIAG_LOG("DWM Hook initialized successfully!");

				break;
			}

			// Log failure reason
			if (!COverlayContext_Present_orig)
				DIAG_LOG("FAILURE: COverlayContext::Present not found");
			if (!COverlayContext_IsCandidateDirectFlipCompatbile_orig)
				DIAG_LOG("FAILURE: COverlayContext::IsCandidateDirectFlipCompatbile not found");
			if (!COverlayContext_OverlaysEnabled_orig)
				DIAG_LOG("FAILURE: COverlayContext::OverlaysEnabled not found");
			if (numLuts == 0)
				DIAG_LOG("FAILURE: No LUTs loaded");
			DIAG_LOG("Returning FALSE from DllMain");
			return FALSE;
		}
	case DLL_PROCESS_DETACH:
		MH_Uninitialize();
		Sleep(100);
		UninitializeStuff();
		break;
	default:
		break;
	}
	return TRUE;
}
