#pragma once

#include <Windows.h>
#include <strsafe.h>

#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Version.lib")

#pragma region "Junk"

inline DECLSPEC_NOINLINE UINT64 GetFileVersion(const WCHAR* filePath)
{
	DWORD dummy;
	DWORD size = GetFileVersionInfoSizeW(filePath, &dummy);
	if (size == 0)
	{
		return {};
	}

	std::vector<char> buffer(size);
	if (!GetFileVersionInfoW(filePath, 0, size, buffer.data()))
	{
		return {};
	}

	VS_FIXEDFILEINFO* fileInfo;
	UINT fileInfoSize;
	if (!VerQueryValueA(buffer.data(), "\\", reinterpret_cast<LPVOID*>(&fileInfo), &fileInfoSize))
	{
		return {};
	}

	return ((UINT64)fileInfo->dwFileVersionMS << 32) | (UINT64)fileInfo->dwFileVersionLS;
}

inline std::wstring GetOriginalFilename(const WCHAR* filePath)
{
	DWORD dummy = 0;
	DWORD size = GetFileVersionInfoSizeW(filePath, &dummy);
	if (size == 0)
	{
		return {};
	}

	std::vector<BYTE> buffer(size);
	if (!GetFileVersionInfoW(filePath, 0, size, buffer.data()))
	{
		return {};
	}

	// Retrieve the language and codepage
	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *translation;

	UINT translationSize = 0;
	if (!VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&translation), &translationSize) || translationSize == 0)
	{
		return {};
	}

	// Use the first translation found
	WCHAR query[64];
	StringCchPrintfW(query, ARRAYSIZE(query), L"\\StringFileInfo\\%04x%04x\\OriginalFilename", translation[0].wLanguage, translation[0].wCodePage);

	LPWSTR originalFilenameValue = nullptr;
	UINT originalFilenameValueSize = 0;
	if (!VerQueryValueW(buffer.data(), query, reinterpret_cast<LPVOID*>(&originalFilenameValue), &originalFilenameValueSize) || originalFilenameValueSize == 0)
	{
		return {};
	}

	return originalFilenameValue;
}

inline DECLSPEC_NOINLINE void* GetExportedFunctionAddress(void* fileBase, const char* functionName)
{
	// Parse the PE headers
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBase);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "Invalid DOS header." << std::endl;
		return nullptr;
	}

	IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)fileBase + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "Invalid NT headers." << std::endl;
		return nullptr;
	}

	// Get the export directory
	IMAGE_DATA_DIRECTORY& dataDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dataDirectory.Size == 0)
	{
		std::cerr << "No export directory found." << std::endl;
		return nullptr;
	}

	DWORD exportRVA = dataDirectory.VirtualAddress;
	if (exportRVA == 0)
	{
		std::cerr << "No export table found.\n";
		return nullptr;
	}

	IMAGE_SECTION_HEADER* pSectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
	IMAGE_SECTION_HEADER* pExportSection = nullptr;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		if (exportRVA >= pSectionHeaders[i].VirtualAddress &&
			exportRVA < pSectionHeaders[i].VirtualAddress + pSectionHeaders[i].Misc.VirtualSize)
		{
			pExportSection = &pSectionHeaders[i];
			break;
		}
	}

	if (!pExportSection)
	{
		std::cerr << "Failed to locate export section.\n";
		return nullptr;
	}

	DWORD exportOffset = exportRVA - pExportSection->VirtualAddress + pExportSection->PointerToRawData;
	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)fileBase + exportOffset);

	// Get arrays of names, ordinals, and function addresses
	DWORD* nameArray = (DWORD*)((BYTE*)fileBase + pExportDir->AddressOfNames - pExportSection->VirtualAddress + pExportSection->PointerToRawData);
	WORD* ordinalArray = (WORD*)((BYTE*)fileBase + pExportDir->AddressOfNameOrdinals - pExportSection->VirtualAddress + pExportSection->PointerToRawData);
	DWORD* functionArray = (DWORD*)((BYTE*)fileBase + pExportDir->AddressOfFunctions - pExportSection->VirtualAddress + pExportSection->PointerToRawData);

	DWORD functionRVA = 0;
	if (IS_INTRESOURCE(functionName))
	{
		// Find the function by ordinal
		WORD ordinal = LOWORD(functionName);
		if (ordinal >= pExportDir->Base && ordinal < pExportDir->Base + pExportDir->NumberOfFunctions)
		{
			functionRVA = functionArray[ordinal - pExportDir->Base];
		}
	}
	else
	{
		// Find the function name in the names array
		for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
		{
			const char* name = (const char*)((BYTE*)fileBase + nameArray[i] - pExportSection->VirtualAddress + pExportSection->PointerToRawData);
			if (strcmp(name, functionName) == 0)
			{
				// Get the function's ordinal and RVA
				WORD ordinal = ordinalArray[i];
				functionRVA = functionArray[ordinal];
			}
		}
	}

	if (!functionRVA)
	{
		std::cerr << "Function not found." << std::endl;
		return nullptr;
	}

	// Calculate the function's address and return it
	IMAGE_SECTION_HEADER* pFunctionSection = nullptr;
	for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; j++)
	{
		if (functionRVA >= pSectionHeaders[j].VirtualAddress &&
			functionRVA < pSectionHeaders[j].VirtualAddress + pSectionHeaders[j].Misc.VirtualSize)
		{
			pFunctionSection = &pSectionHeaders[j];
			break;
		}
	}

	if (!pFunctionSection)
	{
		std::cerr << "Failed to locate function section.\n";
		return nullptr;
	}

	DWORD functionOffset = functionRVA - pFunctionSection->VirtualAddress + pFunctionSection->PointerToRawData;
	void* functionAddress = (BYTE*)fileBase + functionOffset;

	// Cleanup and return the address
	return functionAddress;
}

#define FINDPATTERN_ALG_CLASSIC 1
#define FINDPATTERN_ALG_X86INTRINSICS 3

#define FINDPATTERN_ALG FINDPATTERN_ALG_CLASSIC

#if 1 // FINDPATTERN_ALG == FINDPATTERN_ALG_CLASSIC

inline BOOL MaskCompare(PVOID pBuffer, LPCSTR lpPattern, LPCSTR lpMask)
{
	for (PBYTE value = (PBYTE)pBuffer; *lpMask; ++lpPattern, ++lpMask, ++value)
	{
		if (*lpMask == 'x' && *(LPCBYTE)lpPattern != *value)
			return FALSE;
	}

	return TRUE;
}

/*inline PVOID FindPattern(PVOID pBase, SIZE_T dwSize, LPCSTR lpPattern, LPCSTR lpMask, int* outNumMatches)
{
	// if (outNumMatches)
		// *outNumMatches = 0;
	SIZE_T patternLen = strlen(lpMask);
	dwSize -= patternLen;
	PBYTE firstMatch = nullptr;

	for (SIZE_T index = 0; index <= dwSize; ++index)
	{
		PBYTE pAddress = (PBYTE)pBase + index;

		if (MaskCompare(pAddress, lpPattern, lpMask))
		{
			if (!firstMatch)
				firstMatch = pAddress;
			if (!outNumMatches)
				break;
			++*outNumMatches;
			// break; // REMOVEME for bench
			index += patternLen - 1;
		}
	}

	return firstMatch;
}*/
#endif
#if 1 // #elif 1 // FINDPATTERN_ALG == FINDPATTERN_ALG_X86INTRINSICS

#endif

#include <array>

FORCEINLINE bool _MaskCompareBitLevel_1(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	return (*pbBuffer & *pbMask) == *pbPattern;
}

FORCEINLINE bool _MaskCompareBitLevel_WORD(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	USHORT buffer = *(const UNALIGNED USHORT*)pbBuffer;
	USHORT pattern = *(const UNALIGNED USHORT*)pbPattern;
	USHORT mask = *(const UNALIGNED USHORT*)pbMask;
	return (buffer & mask) == pattern;
}

FORCEINLINE bool _MaskCompareBitLevel_DWORD(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	ULONG buffer = *(const UNALIGNED ULONG*)pbBuffer;
	ULONG pattern = *(const UNALIGNED ULONG*)pbPattern;
	ULONG mask = *(const UNALIGNED ULONG*)pbMask;
	return (buffer & mask) == pattern;
}

FORCEINLINE bool _MaskCompareBitLevel_QWORD(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	ULONGLONG buffer = *(const UNALIGNED ULONGLONG*)pbBuffer;
	ULONGLONG pattern = *(const UNALIGNED ULONGLONG*)pbPattern;
	ULONGLONG mask = *(const UNALIGNED ULONGLONG*)pbMask;
	return (buffer & mask) == pattern;
}

#if defined(_M_X64)
FORCEINLINE bool _MaskCompareBitLevel_SSE2_16(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	__m128i buffer = _mm_loadu_si128((const __m128i*)pbBuffer);
	__m128i pattern = _mm_loadu_si128((const __m128i*)pbPattern);
	__m128i mask = _mm_loadu_si128((const __m128i*)pbMask);
	__m128i eq = _mm_cmpeq_epi8(_mm_and_si128(buffer, mask), pattern);
	return _mm_movemask_epi8(eq) == 0xFFFF;
}
#elif defined(_M_ARM64)
FORCEINLINE bool _MaskCompareBitLevel_NEON_16(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	uint8x16_t buffer = vld1q_u8(pbBuffer);
	uint8x16_t pattern = vld1q_u8(pbPattern);
	uint8x16_t mask = vld1q_u8(pbMask);
	uint8x16_t eq = vceqq_u8(vandq_u8(buffer, mask), pattern);
	return vminvq_u8(eq) == 0xFF;
}
#endif

template <size_t cbPattern>
FORCEINLINE BOOL _MaskCompareBitLevel_Tailored(PBYTE pbBuffer, const BYTE* pbPattern, const BYTE* pbMask)
{
	if constexpr (cbPattern == 0)
	{
		return TRUE;
	}
#if defined(_M_X64)
	else if constexpr (cbPattern >= 16)
	{
		return _MaskCompareBitLevel_SSE2_16(pbBuffer, pbPattern, pbMask)
			&& _MaskCompareBitLevel_Tailored<cbPattern - 16>(pbBuffer + 16, pbPattern + 16, pbMask + 16);
	}
#elif defined(_M_ARM64)
	/*else if constexpr (cbPattern >= 16)
	{
		return _MaskCompareBitLevel_NEON_16(pbBuffer, pbPattern, pbMask)
			&& _MaskCompareBitLevel_Tailored<cbPattern - 16>(pbBuffer + 16, pbPattern + 16, pbMask + 16);
	}*/ // Worse performance
#endif
#ifdef _WIN64
	else if constexpr (cbPattern >= 8)
	{
		return _MaskCompareBitLevel_QWORD(pbBuffer, pbPattern, pbMask)
			&& _MaskCompareBitLevel_Tailored<cbPattern - 8>(pbBuffer + 8, pbPattern + 8, pbMask + 8);
	}
#endif
	else if constexpr (cbPattern >= 4)
	{
		return _MaskCompareBitLevel_DWORD(pbBuffer, pbPattern, pbMask)
			&& _MaskCompareBitLevel_Tailored<cbPattern - 4>(pbBuffer + 4, pbPattern + 4, pbMask + 4);
	}
	else if constexpr (cbPattern >= 2)
	{
		return _MaskCompareBitLevel_WORD(pbBuffer, pbPattern, pbMask)
			&& _MaskCompareBitLevel_Tailored<cbPattern - 2>(pbBuffer + 2, pbPattern + 2, pbMask + 2);
	}
	else
	{
		return _MaskCompareBitLevel_1(pbBuffer, pbPattern, pbMask);
	}
}

template <size_t cbPattern, size_t cbAdvance = 1>
//DECLSPEC_NOINLINE
FORCEINLINE
PVOID _FindPatternWorker(
	PVOID pvSearch, size_t cbSearch, const BYTE* pbPattern, const BYTE* pbMask, int* pcMatches)
{
	// if (outNumMatches)
		// *outNumMatches = 0;
	cbSearch -= cbPattern;
	cbSearch -= cbSearch % cbAdvance; // Round down to multiples of cbAdvance
	PBYTE firstMatch = nullptr;

	PBYTE pBegin = (PBYTE)pvSearch;
	PBYTE pEnd = pBegin + cbSearch;
	for (PBYTE pIt = pBegin; pIt <= pEnd;)
	{
		if (_MaskCompareBitLevel_Tailored<cbPattern>(pIt, pbPattern, pbMask))
		{
			if (!firstMatch)
				firstMatch = pIt;
			if (!pcMatches)
				break;
			++*pcMatches;
			size_t s = cbPattern;
			if constexpr (cbAdvance > 1)
			{
				s -= s % cbAdvance;
				if (s == 0)
				{
					s = cbAdvance;
				}
			}
			pIt += s;
		}
		else
		{
			pIt += cbAdvance;
		}
	}

	return firstMatch;
}

// This BMH variant is only safe when the last byte is fully significant (mask byte is 0xFF)
template <size_t cbPattern, size_t cbAdvance = 1>
//DECLSPEC_NOINLINE
FORCEINLINE
PVOID _FindPatternWorker_BMH(
	PVOID pvSearch, size_t cbSearch, const BYTE* pbPattern, const BYTE* pbMask, const BYTE* prgShift, int* pcMatches)
{
	PBYTE firstMatch = nullptr;
	PBYTE pBegin = (PBYTE)pvSearch;
	PBYTE pEnd = pBegin + (cbSearch - cbPattern);

	size_t iAnchor = cbPattern - 1;
	BYTE bAnchor = pbPattern[iAnchor];

	for (PBYTE pIt = pBegin; pIt <= pEnd;)
	{
		BYTE b = pIt[iAnchor];

		if (b == bAnchor && _MaskCompareBitLevel_Tailored<cbPattern>(pIt, pbPattern, pbMask))
		{
			if (!firstMatch)
				firstMatch = pIt;

			if (!pcMatches)
				break;

			++*pcMatches;

			size_t s = cbPattern;
			if constexpr (cbAdvance > 1)
			{
				s -= s % cbAdvance;
				if (s == 0)
				{
					s = cbAdvance;
				}
			}
			pIt += s;
		}
		else
		{
			pIt += prgShift[b];
		}
	}

	return firstMatch;
}

// Utility structs for compile-time x?x -> 00 FF 00 mask conversion and pattern-mask pair validation

template <std::size_t N>
struct FixedString
{
	char value[N];

	constexpr FixedString(const char (&s)[N])
	{
		for (std::size_t i = 0; i < N; ++i)
		{
			value[i] = s[i];
		}
	}

	static constexpr std::size_t size = N;
};

struct PatternDataTraits_ByteLevelMask
{
	static constexpr BYTE MaskByteForChar(char c)
	{
		return c == 'x' ? 0xFF : 0x00;
	}
};

struct PatternDataTraits_BitLevelMask
{
	static constexpr BYTE MaskByteForChar(char c)
	{
		return static_cast<BYTE>(c);
	}
};

template <FixedString Pattern, FixedString Mask, typename Traits, size_t Advance>
struct PatternData
{
	static_assert(Pattern.size == Mask.size, "Pattern and mask must have the same length");

	static constexpr std::size_t c_cbPattern = Pattern.size - 1;

	static constexpr auto c_rgPatternBytes = []
	{
		std::array<BYTE, c_cbPattern> rgPatternBytes;
		for (std::size_t i = 0; i < c_cbPattern; ++i)
		{
			rgPatternBytes[i] = static_cast<BYTE>(Pattern.value[i]);
		}
		return rgPatternBytes;
	}();

	static constexpr auto c_rgMaskBytes = []
	{
		std::array<BYTE, c_cbPattern> rgMaskBytes;
		for (std::size_t i = 0; i < c_cbPattern; ++i)
		{
			rgMaskBytes[i] = Traits::MaskByteForChar(Mask.value[i]);
		}
		return rgMaskBytes;
	}();

	/*static constexpr size_t c_iBoyerMooreAnchor = []
	{
		for (size_t i = c_cbPattern; i-- > 0;)
		{
			if (c_rgMaskBytes[i] == 0xFF)
			{
				return i;
			}
		}
		return c_cbPattern;
	}();*/

	static constexpr auto c_rgBoyerMooreShift = []
	{
		std::array<BYTE, 256> rgShift;

		constexpr size_t iAnchor = c_cbPattern - 1;

		for (size_t i = 0; i < 256; ++i)
		{
			rgShift[i] = static_cast<BYTE>(iAnchor + 1);
		}

		// For each possible anchor byte value, find the rightmost compatible position before the anchor.
		for (size_t c = 0; c < 256; ++c)
		{
			BYTE b = static_cast<BYTE>(c);

			for (size_t i = iAnchor; i-- > 0;)
			{
				if ((b & c_rgMaskBytes[i]) == c_rgPatternBytes[i])
				{
					rgShift[c] = static_cast<BYTE>(iAnchor - i);
					break;
				}
			}
		}

		if constexpr (Advance > 1)
		{
			for (size_t i = 0; i < 256; ++i)
			{
				size_t s = rgShift[i];
				s -= s % Advance;
				if (s == 0)
				{
					s = Advance;
				}
				rgShift[i] = static_cast<BYTE>(s);
			}
		}

		return rgShift;
	}();

	static constexpr bool Validate(
		const std::array<BYTE, c_cbPattern>& pattern, const std::array<BYTE, c_cbPattern>& mask)
	{
		for (std::size_t i = 0; i < c_cbPattern; ++i)
		{
			if ((pattern[i] & ~mask[i]) != 0)
			{
				return false;
			}
		}
		return true;
	}

	static_assert(c_cbPattern <= UINT8_MAX, "Pattern length must be 255 bytes or less");
	static_assert(Validate(c_rgPatternBytes, c_rgMaskBytes), "Invalid pattern/mask combination");
	static_assert(c_rgMaskBytes.back() == 0xFF, "The last byte must be fully significant");
};

template <FixedString Pattern, FixedString Mask, typename Traits, size_t Advance>
FORCEINLINE PVOID _FindPattern(PVOID pvSearch, size_t cbSearch, int* pcMatches)
{
	using Data = PatternData<Pattern, Mask, Traits, Advance>;
	if constexpr (false/*Data::c_iBoyerMooreAnchor == Data::c_cbPattern - 1*/)
	{
		return _FindPatternWorker_BMH<Data::c_cbPattern, Advance>(
			pvSearch, cbSearch, Data::c_rgPatternBytes.data(), Data::c_rgMaskBytes.data(),
			Data::c_rgBoyerMooreShift.data(), pcMatches);
	}
	else
	{
		return _FindPatternWorker<Data::c_cbPattern, Advance>(
			pvSearch, cbSearch, Data::c_rgPatternBytes.data(), Data::c_rgMaskBytes.data(),
			pcMatches);
	}
}

// Byte-level mask, advance 1 byte

#define FindPattern(pvSearch, cbSearch, pszPattern, pszMask, pcMatches) \
	_FindPattern<pszPattern, pszMask, PatternDataTraits_ByteLevelMask, 1>((pvSearch), (cbSearch), (pcMatches))

// Byte-level mask, advance 4 bytes

#define FindPattern_4_(pvSearch, cbSearch, pszPattern, pszMask, pcMatches) \
	_FindPattern<pszPattern, pszMask, PatternDataTraits_ByteLevelMask, 4>((pvSearch), (cbSearch), (pcMatches))

// Bit-level mask, advance 1 byte

#define FindPatternBitMask(pvSearch, cbSearch, pszPattern, pszMask, cbPatternIgnored, pcMatches) \
	_FindPattern<pszPattern, pszMask, PatternDataTraits_BitLevelMask, 1>((pvSearch), (cbSearch), (pcMatches))

// Bit-level mask, advance 4 bytes

#define FindPatternBitMask_4_(pvSearch, cbSearch, pszPattern, pszMask, cbPatternIgnored, pcMatches) \
	_FindPattern<pszPattern, pszMask, PatternDataTraits_BitLevelMask, 4>((pvSearch), (cbSearch), (pcMatches))

inline UINT_PTR FileOffsetToRVA(PBYTE pBase, UINT_PTR offset)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
	{
		if (offset >= pSection->PointerToRawData && offset < pSection->PointerToRawData + pSection->SizeOfRawData)
			return offset - pSection->PointerToRawData + pSection->VirtualAddress;
	}
	return 0;
}

// ----------

inline std::string WideToUtf8(const std::wstring& s)
{
	if (s.empty())
		return {};

	int cch = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
	if (cch <= 0)
		return {};

	std::string result((size_t)cch, '\0');
	WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), result.data(), cch, nullptr, nullptr);
	return result;
}

inline std::wstring Utf8ToWide(const std::string& s)
{
	if (s.empty())
		return {};

	int cch = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
	if (cch <= 0)
		return {};

	std::wstring result((size_t)cch, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), result.data(), cch);
	return result;
}

inline std::wstring MakeDefaultResultBaseNameUtc()
{
	SYSTEMTIME st{};
	GetSystemTime(&st);

	WCHAR sz[64];
	swprintf_s(
		sz,
		L"results-%04u-%02u-%02uT%02u-%02u-%02uZ",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	return sz;
}

inline std::wstring GetWorkerResultsPath(const std::wstring& resultBaseName, const wchar_t* pszExtension)
{
	return L"WorkerResults\\" + resultBaseName + pszExtension;
}

inline bool EnsureWorkerResultsDirectory()
{
	if (CreateDirectoryW(L"WorkerResults", nullptr))
		return true;

	DWORD dwError = GetLastError();
	return dwError == ERROR_ALREADY_EXISTS;
}

inline bool ReadUtf8Lines(const std::wstring& path, std::vector<std::wstring>* pLines)
{
	pLines->clear();

	FILE* fp;
	errno_t err = _wfopen_s(&fp, path.c_str(), L"rb");
	if (err != 0)
		return false;

	std::unique_ptr<FILE, decltype(&fclose)> spFile(fp, fclose);

	if (fseek(fp, 0, SEEK_END) != 0)
		return false;

	long cbFile = ftell(fp);
	if (cbFile < 0)
		return false;

	if (fseek(fp, 0, SEEK_SET) != 0)
		return false;

	std::string bytes;
	bytes.resize((size_t)cbFile);

	if (cbFile > 0)
	{
		size_t cbRead = fread(bytes.data(), 1, (size_t)cbFile, fp);
		if (cbRead != (size_t)cbFile)
			return false;
	}

	size_t start = 0;

	// Skip UTF-8 BOM if present.
	if (bytes.size() >= 3 &&
		(BYTE)bytes[0] == 0xEF &&
		(BYTE)bytes[1] == 0xBB &&
		(BYTE)bytes[2] == 0xBF)
	{
		start = 3;
	}

	while (start <= bytes.size())
	{
		size_t end = bytes.find('\n', start);
		if (end == std::string::npos)
			end = bytes.size();

		std::string line = bytes.substr(start, end - start);
		if (!line.empty() && line.back() == '\r')
			line.pop_back();

		if (!line.empty())
			pLines->push_back(Utf8ToWide(line));

		if (end == bytes.size())
			break;

		start = end + 1;
	}

	return true;
}

inline const char* MachineTypeToArchKey(WORD machineType)
{
	switch (machineType)
	{
		case IMAGE_FILE_MACHINE_AMD64:
			return "amd64";

		case IMAGE_FILE_MACHINE_ARM64:
			return "arm64";

		default:
			return nullptr;
	}
}

inline std::wstring FileVersionToWorkerVersionString(UINT64 fileVersion)
{
	DWORD ls = (fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileVersion >> 32) & 0xFFFFFFFF;

	WORD major = HIWORD(ms);
	WORD minor = LOWORD(ms);
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	WCHAR szVersion[64];
	swprintf_s(szVersion, L"%u.%u.%u.%u", major, minor, build, ubr);
	return szVersion;
}

// ----------

#define INIT_MATCH_INFO_VARS(name) \
	PBYTE match##name = nullptr; \
	int numMatches##name = 0; \
	int usingPattern##name = 0

#define PUBLISH_MATCH_INFO(name) \
	{ \
		matches->emplace_back(numMatches##name, usingPattern##name); \
	}

struct FileInfo
{
	std::wstring fileName;
	std::wstring filePath;
	UINT64 fileVersion; // For hash key
	WORD machineType; // For hash key

	bool operator==(const FileInfo& other) const
	{
		return fileVersion == other.fileVersion && machineType == other.machineType;
	}
};

struct FileInfoComparator
{
	bool operator()(const FileInfo& a, const FileInfo& b) const
	{
		DWORD a_ls = (a.fileVersion >> 0) & 0xFFFFFFFF;
		DWORD b_ls = (b.fileVersion >> 0) & 0xFFFFFFFF;
		DWORD a_a = HIWORD(a_ls), a_b = LOWORD(a_ls);
		DWORD b_a = HIWORD(b_ls), b_b = LOWORD(b_ls);
		if (a_a != b_a)
			return a_a < b_a;
		if (a_b != b_b)
			return a_b < b_b;
		return a.machineType < b.machineType;
	}
};

struct FileInfoHash
{
	size_t operator()(const FileInfo& info) const noexcept
	{
		DWORD ls = (info.fileVersion >> 0) & 0xFFFFFFFF;
		DWORD a = HIWORD(ls), b = LOWORD(ls);
		return std::hash<DWORD>()(a) ^ std::hash<DWORD>()(b) ^ std::hash<WORD>()(info.machineType);
	}
};

struct FileInfoEqual
{
	bool operator()(const FileInfo& a, const FileInfo& b) const
	{
		return a.fileVersion == b.fileVersion && a.machineType == b.machineType;
	}
};

#pragma endregion "Junk"

class CPatternCheckerSuiteModule_Base : public std::enable_shared_from_this<CPatternCheckerSuiteModule_Base>
{
public:
	struct ElementDef
	{
		const WCHAR* m_shortName;
		const WCHAR* m_longName;
	};

protected:
	CPatternCheckerSuiteModule_Base(const WCHAR* moduleName, const std::span<const ElementDef>& elementDefs);

	virtual ~CPatternCheckerSuiteModule_Base() = default;

public:
	struct PatternMatchInfo
	{
		int numMatches;
		int usingPattern;

		PatternMatchInfo(int numMatches, int usingPattern)
			: numMatches(numMatches)
			, usingPattern(usingPattern)
		{
		}
	};

	const WCHAR* GetModuleName() const;
	const std::span<const ElementDef>& GetElementDefs() const;

	// Virtuals
	virtual void CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches) = 0;
	virtual bool ShouldIncludeFile(const FileInfo& fileInfo) const;
	virtual void PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches);

	std::unordered_map<FileInfo, std::vector<PatternMatchInfo>, FileInfoHash, FileInfoEqual> m_matches;
	std::mutex m_matchesLock;

protected:
	const WCHAR* const m_moduleName;
	std::span<const ElementDef> m_elementDefs;
};

inline CPatternCheckerSuiteModule_Base::CPatternCheckerSuiteModule_Base(const WCHAR* moduleName, const std::span<const ElementDef>& elementDefs)
	: m_moduleName(moduleName)
	, m_elementDefs(elementDefs)
{
}

inline const WCHAR* CPatternCheckerSuiteModule_Base::GetModuleName() const
{
	return m_moduleName;
}

inline const std::span<const CPatternCheckerSuiteModule_Base::ElementDef>& CPatternCheckerSuiteModule_Base::GetElementDefs() const
{
	return m_elementDefs;
}

inline bool CPatternCheckerSuiteModule_Base::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	/*if (true) // REMOVEME
		{
			DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
			DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
			WORD build = HIWORD(ls);
			WORD ubr = LOWORD(ls);

			bool b = build == 22621 && ubr == 3880;
			if (!b)
				return false;
		}*/
	return fileInfo.machineType == IMAGE_FILE_MACHINE_AMD64 || fileInfo.machineType == IMAGE_FILE_MACHINE_ARM64;
}

inline void CPatternCheckerSuiteModule_Base::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	if (matches->size() != m_elementDefs.size())
	{
		__fastfail(FAST_FAIL_INVALID_ARG);
	}
}

inline int MatchInfoToWorkerCode(const CPatternCheckerSuiteModule_Base::PatternMatchInfo& matchInfo)
{
	if (matchInfo.numMatches == 0)
		return 0;
	if (matchInfo.numMatches == 1)
		return 2;
	if (matchInfo.numMatches == -1)
		return 3;
	return 1;
}
