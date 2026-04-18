#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <queue>
#include <ranges>
#include <set>
#include <sstream>

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <wil/resource.h>

#include "PatternCheckerSuiteModule_Base.h"
#include "PatternCheckerSuiteModule_Explorer.h"
#include "PatternCheckerSuiteModule_InputSwitch.h"
#include "PatternCheckerSuiteModule_StartTileData.h"
#include "PatternCheckerSuiteModule_TwinUIPCShell.h"
#include "PatternCheckerSuiteModule_UxTheme.h"

inline UINT_PTR RVAToFileOffset(PBYTE pBase, DWORD fileSize, UINT_PTR rva)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
	{
		DWORD va = pSection->VirtualAddress;
		DWORD vs = pSection->Misc.VirtualSize;

		if (rva >= va && rva < va + vs)
		{
			DWORD raw = (DWORD)(pSection->PointerToRawData + (rva - va));
			return raw < fileSize ? raw : 0;
		}
	}
	return 0;
}

typedef struct _IMAGE_CHPE_RANGE_ENTRY
{
	union
	{
		ULONG StartOffset;
		struct
		{
			ULONG NativeCode : 1;
			ULONG AddressBits : 31;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	ULONG Length;
} IMAGE_CHPE_RANGE_ENTRY, *PIMAGE_CHPE_RANGE_ENTRY;

typedef struct _IMAGE_ARM64EC_METADATA
{
	ULONG  Version;
	ULONG  CodeMap;
	ULONG  CodeMapCount;
	ULONG  CodeRangesToEntryPoints;
	ULONG  RedirectionMetadata;
	ULONG  __os_arm64x_dispatch_call_no_redirect;
	ULONG  __os_arm64x_dispatch_ret;
	ULONG  __os_arm64x_dispatch_call;
	ULONG  __os_arm64x_dispatch_icall;
	ULONG  __os_arm64x_dispatch_icall_cfg;
	ULONG  AlternateEntryPoint;
	ULONG  AuxiliaryIAT;
	ULONG  CodeRangesToEntryPointsCount;
	ULONG  RedirectionMetadataCount;
	ULONG  GetX64InformationFunctionPointer;
	ULONG  SetX64InformationFunctionPointer;
	ULONG  ExtraRFETable;
	ULONG  ExtraRFETableSize;
	ULONG  __os_arm64x_dispatch_fptr;
	ULONG  AuxiliaryIATCopy;
} IMAGE_ARM64EC_METADATA;

template <typename IMAGE_NT_HEADERS_T, typename IMAGE_LOAD_CONFIG_DIRECTORY_T>
std::optional<std::span<const IMAGE_CHPE_RANGE_ENTRY>>
GetChpeRangesFromRaw(
    PBYTE pFileBase,
    DWORD fileSize,
    const IMAGE_DOS_HEADER* dosHeader,
    const IMAGE_NT_HEADERS_T* ntHeader)
{
    auto* opt = &ntHeader->OptionalHeader;

    if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ||
        !opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress)
    {
        return std::nullopt;
    }

    DWORD directoryRVA  = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    DWORD directorySize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
	UINT64 imageBase    = opt->ImageBase;

    UINT_PTR dirOffset = RVAToFileOffset(pFileBase, fileSize, directoryRVA);
    if (!dirOffset || dirOffset + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY_T) > fileSize)
        return std::nullopt;

    const IMAGE_LOAD_CONFIG_DIRECTORY_T* cfg =
        (const IMAGE_LOAD_CONFIG_DIRECTORY_T*)(pFileBase + dirOffset);

    constexpr DWORD kMinSize =
        offsetof(IMAGE_LOAD_CONFIG_DIRECTORY_T, CHPEMetadataPointer) +
        sizeof(IMAGE_LOAD_CONFIG_DIRECTORY_T::CHPEMetadataPointer);

    if (directorySize < kMinSize || cfg->Size < kMinSize)
        return std::nullopt;

    if (!cfg->CHPEMetadataPointer)
        return std::nullopt;

	auto metadataVA  = cfg->CHPEMetadataPointer;
	auto metadataRVA = metadataVA - imageBase;

	UINT_PTR metadataOffset = RVAToFileOffset(pFileBase, fileSize, metadataRVA);
	if (!metadataOffset || metadataOffset + sizeof(IMAGE_ARM64EC_METADATA) > fileSize)
		return std::nullopt;

	const IMAGE_ARM64EC_METADATA* metadata =
		(const IMAGE_ARM64EC_METADATA*)(pFileBase + metadataOffset);

    UINT_PTR codeMapOffset = RVAToFileOffset(pFileBase, fileSize, metadata->CodeMap);
	if (!codeMapOffset)
		return std::nullopt;

	const IMAGE_CHPE_RANGE_ENTRY* codeMap =
		(const IMAGE_CHPE_RANGE_ENTRY*)(pFileBase + codeMapOffset);

	return std::span(codeMap, metadata->CodeMapCount);
}

inline void SectionBeginAndSizeOfPEFile(
	PBYTE pFileBase,
	DWORD fileSize,
	const char* pszSectionName,
	PBYTE* beginSection,
	DWORD* sizeSection)
{
	*beginSection = nullptr;
	*sizeSection = 0;

	if (!pFileBase || fileSize < sizeof(IMAGE_DOS_HEADER))
		return;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	// NT header must be inside file
	if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize)
		return;

	PIMAGE_NT_HEADERS64 ntHeader =
		(PIMAGE_NT_HEADERS64)(pFileBase + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(ntHeader);

	for (unsigned int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = firstSection + i;

		if (strncmp((const char*)section->Name, pszSectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			DWORD rawOffset = section->PointerToRawData;
			DWORD rawSize   = section->SizeOfRawData;

			// Bounds check inside file
			if (rawOffset + rawSize <= fileSize)
			{
				*beginSection = pFileBase + rawOffset;
				*sizeSection = rawSize;
			}
			return;
		}
	}
}

__forceinline void TextSectionBeginAndSizeOfPEFile(
	PBYTE pFileBase,
	DWORD fileSize,
	PBYTE* beginSection,
	DWORD* sizeSection)
{
	SectionBeginAndSizeOfPEFile(pFileBase, fileSize, ".text", beginSection, sizeSection);
}

class CPatternCheckerSuite
{
public:
	void RegisterModule(const std::shared_ptr<CPatternCheckerSuiteModule_Base>& module);
	void StartWorkers(std::vector<std::thread>& rgWorkers);
	void FinishWorkers(std::vector<std::thread>& rgWorkers);
	void Reset();
	// void OldTraverseDirectory(const std::wstring& directoryPath);
	// void OldRun();
	void TraverseDirectory(const std::wstring& directoryPath);
	void RunFull(const std::vector<std::wstring>& rgDirectories, const std::wstring& resultBaseName, bool bWriteHtml);
	void RunSpecificFiles(const std::vector<std::wstring>& rgFiles, const std::wstring& resultBaseName);
	size_t GetProcessedFileCount() const;

private:
	struct CandidateFile
	{
		std::wstring filePath;
	};

	struct MatchSlot
	{
		std::shared_ptr<CPatternCheckerSuiteModule_Base> module;
		FileInfo fileInfo;
		std::vector<CPatternCheckerSuiteModule_Base::PatternMatchInfo>* matches;
	};

	bool TryReadPeIdentity(
		const std::wstring& fullPath, std::wstring* originalFilename, UINT64* fileVersion, WORD* machineType,
		HANDLE* phFile);
	// static bool TryMapReadOnlyFile(HANDLE hFile, HANDLE* phMapping, BYTE** ppbMapView, DWORD* pdwFileSize);
	static bool TryReadWholeFile(HANDLE hFile, std::vector<BYTE>* prgBuffer, DWORD* pdwFileSize);
	static bool TryGetTextSearchRegion(PBYTE pFile, DWORD dwSize, WORD machineType, PBYTE* ppSearchBegin, DWORD* pdwSearchSize);
	void EnqueueFile(const std::wstring& fullPath);

	bool TryReserveMatchSlots(const FileInfo& fileInfo, MatchSlot* pMatchSlot);
	void WorkerThreadProc();
	void WriteJsonReport(const std::wstring& resultBaseName, double elapsedTime);
	void WriteHtmlReport(const std::wstring& resultBaseName);
	void PrintForModuleAndMachineType(const std::shared_ptr<CPatternCheckerSuiteModule_Base>& module, std::wstringstream& md, WORD machineType);

	// std::vector<FileInfo> m_fileInfos;
	std::map<std::wstring, std::shared_ptr<CPatternCheckerSuiteModule_Base>> m_modules;
	std::queue<CandidateFile> m_queue;
	std::mutex m_queueLock;
	std::condition_variable m_queueCv;
	std::atomic<size_t> m_cProcessedFiles = 0;
	bool m_doneEnumerating = false;

	static constexpr size_t c_maxQueuedFiles = 1024;
};

void CPatternCheckerSuite::RegisterModule(const std::shared_ptr<CPatternCheckerSuiteModule_Base>& module)
{
	m_modules[module->GetModuleName()] = module;
}

/*void CPatternCheckerSuite::OldTraverseDirectory(const std::wstring& directoryPath)
{
	WIN32_FIND_DATAW findFileData;
	HANDLE hFind = FindFirstFileW((directoryPath + L"\\*").c_str(), &findFileData);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		return;
	}

	do
	{
		const std::wstring fileOrDirName = findFileData.cFileName;
		const std::wstring fullPath = directoryPath + L"\\" + fileOrDirName;

		if (fileOrDirName == L"." || fileOrDirName == L"..")
		{
			continue;
		}

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			OldTraverseDirectory(fullPath);
			continue;
		}

		// Check extension
		const std::wstring::size_type dotPos = fileOrDirName.rfind(L'.');
		if (dotPos == std::wstring::npos)
		{
			continue;
		}

		const std::wstring extension = fileOrDirName.substr(dotPos + 1);
		if (extension != L"exe" && extension != L"dll" && extension != L"blob")
		{
			continue;
		}

		HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			continue;
		}

		IMAGE_DOS_HEADER dosHeader;
		DWORD dwRead = 0;
		if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &dwRead, nullptr) && dwRead == sizeof(dosHeader) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE)
		{
			IMAGE_NT_HEADERS64 ntHeader;
			SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN);
			if (ReadFile(hFile, &ntHeader, sizeof(ntHeader), &dwRead, nullptr) && dwRead == sizeof(ntHeader) && ntHeader.Signature == IMAGE_NT_SIGNATURE)
			{
				std::wstring originalFilename = GetOriginalFilename(fullPath.c_str());
				if (!originalFilename.empty())
				{
					auto pair = m_modules.find(originalFilename);
					if (pair != m_modules.end())
					{
						FileInfo info;
						info.fileName = originalFilename;
						info.filePath = fullPath;
						info.fileVersion = GetFileVersion(fullPath.c_str());
						info.machineType = ntHeader.FileHeader.Machine;
						wprintf(L"%s\n", info.filePath.c_str());
						m_fileInfos.push_back(info);
					}
				}
			}
		}

		CloseHandle(hFile);
	}
	while (FindNextFileW(hFind, &findFileData) != 0);

	FindClose(hFind);
}

void CPatternCheckerSuite::OldRun()
{
	std::for_each(std::execution::par_unseq, m_fileInfos.begin(), m_fileInfos.end(), [&](const FileInfo& fileInfo) -> void
	{
		const std::shared_ptr<CPatternCheckerSuiteModule_Base>& module = m_modules[fileInfo.fileName];
		if (!module->ShouldIncludeFile(fileInfo))
		{
			return;
		}

		HANDLE hFile = CreateFileW(fileInfo.filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"Failed to open %s\n", fileInfo.filePath.c_str());
			return;
		}

		DWORD dwSize = GetFileSize(hFile, nullptr);
		PBYTE pFile = (PBYTE)malloc(dwSize);
		DWORD dwRead = 0;
		if (!ReadFile(hFile, pFile, dwSize, &dwRead, nullptr) || dwRead != dwSize)
		{
			wprintf(L"Failed to read %s\n", fileInfo.filePath.c_str());
			return;
		}

		module->m_matchesLock.lock();
		auto pair = module->m_matches.find(fileInfo);
		std::vector<CPatternCheckerSuiteModule_Base::PatternMatchInfo>* pMatchInfos = pair == module->m_matches.end()
			                                                                              ? &module->m_matches[fileInfo] : nullptr;
		module->m_matchesLock.unlock();
		if (pMatchInfos)
		{
			PBYTE pbSearchBegin = nullptr;
			DWORD dwSearchSize = 0;
			if (!TryGetTextSearchRegion(hFile, dwSize, fileInfo.machineType, &pbSearchBegin, &dwSearchSize))
			{
				wprintf(L"Failed to get search region for %s\n", fileInfo.filePath.c_str());
				return;
			}

			module->CheckPatterns(pFile, dwSize, pbSearchBegin, dwSearchSize, fileInfo.machineType, pMatchInfos);
		}
		else
		{
			// We've processed this file already
		}
	});

	WriteHtmlReport();
}*/

void CPatternCheckerSuite::StartWorkers(std::vector<std::thread>& rgWorkers)
{
	const size_t cThreads = std::max<size_t>(1, std::thread::hardware_concurrency());
	rgWorkers.reserve(cThreads);

	for (size_t i = 0; i < cThreads; ++i)
	{
		rgWorkers.emplace_back([this]
		{
			WorkerThreadProc();
		});
	}
}

void CPatternCheckerSuite::FinishWorkers(std::vector<std::thread>& rgWorkers)
{
	{
		std::lock_guard lock(m_queueLock);
		m_doneEnumerating = true;
	}
	m_queueCv.notify_all();

	for (std::thread& worker : rgWorkers)
	{
		worker.join();
	}
}

void CPatternCheckerSuite::Reset()
{
	m_cProcessedFiles = 0;
	m_doneEnumerating = false;
}

void CPatternCheckerSuite::RunFull(
	const std::vector<std::wstring>& rgDirectories, const std::wstring& resultBaseName, bool bWriteHtml)
{
	LARGE_INTEGER startTime;
	QueryPerformanceCounter(&startTime);

	Reset();

	std::vector<std::thread> workers;
	StartWorkers(workers);

	for (const auto& directory : rgDirectories)
	{
		TraverseDirectory(directory);
	}

	FinishWorkers(workers);

	LARGE_INTEGER endTime;
	QueryPerformanceCounter(&endTime);
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	double elapsedTime = static_cast<double>(endTime.QuadPart - startTime.QuadPart) / static_cast<double>(freq.QuadPart);
	wprintf(L"%.3f seconds\n", elapsedTime);

	if (m_cProcessedFiles.load() != 0)
	{
		WriteJsonReport(resultBaseName, elapsedTime);
		if (bWriteHtml)
		{
			WriteHtmlReport(resultBaseName);
		}
	}
}

void CPatternCheckerSuite::RunSpecificFiles(const std::vector<std::wstring>& rgFiles, const std::wstring& resultBaseName)
{
	LARGE_INTEGER startTime;
	QueryPerformanceCounter(&startTime);

	Reset();

	std::vector<std::thread> workers;
	StartWorkers(workers);

	for (const auto& file : rgFiles)
	{
		EnqueueFile(file);
	}

	FinishWorkers(workers);

	LARGE_INTEGER endTime;
	QueryPerformanceCounter(&endTime);
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	double elapsedTime = static_cast<double>(endTime.QuadPart - startTime.QuadPart) / static_cast<double>(freq.QuadPart);
	wprintf(L"%.3f seconds\n", elapsedTime);

	if (m_cProcessedFiles.load() != 0)
	{
		WriteJsonReport(resultBaseName, elapsedTime);
	}
}

size_t CPatternCheckerSuite::GetProcessedFileCount() const
{
	return m_cProcessedFiles.load();
}

bool CPatternCheckerSuite::TryReadPeIdentity(
	const std::wstring& fullPath, std::wstring* originalFilename, UINT64* fileVersion, WORD* machineType,
	HANDLE* phFile)
{
	*fileVersion = 0;
	*machineType = 0;
	*phFile = INVALID_HANDLE_VALUE;

	// Early check if this file is what we want checked
	*originalFilename = GetOriginalFilename(fullPath.c_str());
	if (originalFilename->empty() || !m_modules.contains(*originalFilename))
	{
		return false;
	}

	wil::unique_hfile hFile(CreateFileW(
		fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL /*| FILE_FLAG_SEQUENTIAL_SCAN*/, nullptr));

	if (!hFile || hFile.get() == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	IMAGE_DOS_HEADER dosHeader{};
	DWORD dwRead = 0;
	if (!ReadFile(hFile.get(), &dosHeader, sizeof(dosHeader), &dwRead, nullptr) ||
		dwRead != sizeof(dosHeader) ||
		dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	if (dosHeader.e_lfanew < 0)
	{
		return false;
	}

	LONG newPos = SetFilePointer(hFile.get(), dosHeader.e_lfanew, nullptr, FILE_BEGIN);
	if (newPos == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
	{
		return false;
	}

	IMAGE_NT_HEADERS64 ntHeaders{};
	if (!ReadFile(hFile.get(), &ntHeaders, sizeof(ntHeaders), &dwRead, nullptr) ||
		dwRead < offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + sizeof(ntHeaders.OptionalHeader) ||
		ntHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	*machineType = ntHeaders.FileHeader.Machine;

	*fileVersion = GetFileVersion(fullPath.c_str());
	*phFile = hFile.release();
	return true;
}

// bool CPatternCheckerSuite::TryMapReadOnlyFile(HANDLE hFile, HANDLE* phMapping, BYTE** ppbMapView, DWORD* pdwFileSize)
bool CPatternCheckerSuite::TryReadWholeFile(HANDLE hFile, std::vector<BYTE>* prgBuffer, DWORD* pdwFileSize)
{
	// *phMapping = nullptr;
	// *ppbMapView = nullptr;
	*pdwFileSize = 0;

	LARGE_INTEGER size{};
	if (!GetFileSizeEx(hFile, &size) || size.QuadPart <= 0 || size.QuadPart > MAXDWORD)
	{
		return false;
	}

	*pdwFileSize = static_cast<DWORD>(size.QuadPart);

	/**phMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!*phMapping)
	{
		return false;
	}

	*ppbMapView = static_cast<BYTE*>(MapViewOfFile(*phMapping, FILE_MAP_READ, 0, 0, 0));
	if (!*ppbMapView)
	{
		return false;
	}*/

	if (SetFilePointer(hFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
		GetLastError() != NO_ERROR)
	{
		return false;
	}

	if (prgBuffer->capacity() < *pdwFileSize)
	{
		prgBuffer->reserve(*pdwFileSize);
	}
	prgBuffer->resize(*pdwFileSize);

	DWORD dwRead = 0;
	if (!ReadFile(hFile, prgBuffer->data(), *pdwFileSize, &dwRead, nullptr) || dwRead != *pdwFileSize)
	{
		return false;
	}

	return true;
}

bool CPatternCheckerSuite::TryGetTextSearchRegion(
	PBYTE pFile, DWORD dwSize, WORD machineType, PBYTE* ppSearchBegin, DWORD* pdwSearchSize)
{
	*ppSearchBegin = nullptr;
	*pdwSearchSize = 0;

	PBYTE pbSearchBegin = nullptr;
	DWORD dwSearchSize = 0;
	TextSectionBeginAndSizeOfPEFile(pFile, dwSize, &pbSearchBegin, &dwSearchSize);
	if (!pbSearchBegin || dwSearchSize == 0)
	{
		//wprintf(L"Failed to get .text section of %s\n", fileInfo.filePath.c_str());
		return false;
	}

	const IMAGE_DOS_HEADER* dosHeader = (const IMAGE_DOS_HEADER*)pFile;
	const IMAGE_NT_HEADERS* ntHeader = (const IMAGE_NT_HEADERS*)((const char*)dosHeader + dosHeader->e_lfanew);

	if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::optional<std::span<const IMAGE_CHPE_RANGE_ENTRY>> chpeRanges =
			GetChpeRangesFromRaw<IMAGE_NT_HEADERS64, IMAGE_LOAD_CONFIG_DIRECTORY64>(
				pFile, dwSize, dosHeader, ntHeader);
		if (chpeRanges)
		{
			for (const IMAGE_CHPE_RANGE_ENTRY& range : *chpeRanges)
			{
				ULONG typeMask = 3;
				ULONG start = range.StartOffset & ~typeMask; // RVA
				ULONG type = range.StartOffset & typeMask; // 0 = Arm64, 1 = Arm64EC, 2 = Amd64
				if (type == 0) // Arm64
				{
					UINT_PTR fileOffset = RVAToFileOffset(pFile, dwSize, start);
					if (!fileOffset || fileOffset + range.Length > dwSize)
					{
						//wprintf(L"Invalid CHPE range in %s\n", fileInfo.filePath.c_str());
						return false;
					}

					pbSearchBegin = pFile + fileOffset;
					dwSearchSize = range.Length;
				}
			}
		}
	}

	*ppSearchBegin = pbSearchBegin;
	*pdwSearchSize = dwSearchSize;
	UNREFERENCED_PARAMETER(machineType);
	return true;
}

void CPatternCheckerSuite::EnqueueFile(const std::wstring& fullPath)
{
	{
		std::unique_lock lock(m_queueLock);
		m_queueCv.wait(lock, [this]
		{
			return m_queue.size() < c_maxQueuedFiles;
		});
		m_queue.push({ fullPath });
	}
	m_queueCv.notify_one();
}

void CPatternCheckerSuite::TraverseDirectory(const std::wstring& directoryPath)
{
	WIN32_FIND_DATAW findFileData{};
	wil::unique_hfind hFind(FindFirstFileW((directoryPath + L"\\*").c_str(), &findFileData));
	if (!hFind || hFind.get() == INVALID_HANDLE_VALUE)
	{
		return;
	}

	do
	{
		const std::wstring fileOrDirName = findFileData.cFileName;
		if (fileOrDirName == L"." || fileOrDirName == L"..")
		{
			continue;
		}

		const std::wstring fullPath = directoryPath + L"\\" + fileOrDirName;

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			TraverseDirectory(fullPath);
			continue;
		}

		const std::wstring::size_type dotPos = fileOrDirName.rfind(L'.');
		if (dotPos == std::wstring::npos)
		{
			continue;
		}

		std::wstring extension = fileOrDirName.substr(dotPos + 1);
		std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
		if (extension != L"exe" && extension != L"dll" && extension != L"blob")
		{
			continue;
		}

		EnqueueFile(fullPath);
	}
	while (FindNextFileW(hFind.get(), &findFileData));
}

bool CPatternCheckerSuite::TryReserveMatchSlots(const FileInfo& fileInfo, MatchSlot* pMatchSlot)
{
	auto it = m_modules.find(fileInfo.fileName);
	if (it == m_modules.end())
	{
		return false;
	}

	auto& module = it->second;
	if (!module->ShouldIncludeFile(fileInfo))
	{
		return false;
	}

	std::lock_guard lock(module->m_matchesLock);
	auto [it2, inserted] = module->m_matches.try_emplace(fileInfo);
	if (!inserted)
	{
		return false;
	}

	*pMatchSlot = MatchSlot{ module, fileInfo, &it2->second };
	return true;
}

void CPatternCheckerSuite::WorkerThreadProc()
{
	std::vector<BYTE> rgScratchBuffer;
	for (;;)
	{
		CandidateFile item;

		{
			std::unique_lock lock(m_queueLock);
			m_queueCv.wait(lock, [this]
			{
				return m_doneEnumerating || !m_queue.empty();
			});

			if (m_queue.empty())
			{
				if (m_doneEnumerating)
				{
					return;
				}
				continue;
			}

			item = std::move(m_queue.front());
			m_queue.pop();
		}
		m_queueCv.notify_one();

		std::wstring originalFilename;
		UINT64 fileVersion = 0;
		WORD machineType = 0;

		wil::unique_hfile hFile;
		if (!TryReadPeIdentity(item.filePath, &originalFilename, &fileVersion, &machineType, &hFile))
		{
			continue;
		}

		auto pair = m_modules.find(originalFilename);
		if (pair == m_modules.end())
		{
			continue;
		}

		FileInfo fileInfo{
			.fileName = std::move(originalFilename),
			.filePath = item.filePath,
			.fileVersion = fileVersion,
			.machineType = machineType,
		};

		MatchSlot slot;
		if (!TryReserveMatchSlots(fileInfo, &slot))
		{
			continue;
		}

		++m_cProcessedFiles;
		// wprintf(L"%s\n", fileInfo.filePath.c_str());

		DWORD fileSize = 0;
		if (!TryReadWholeFile(hFile.get(), &rgScratchBuffer, &fileSize))
		{
			wprintf(L"Failed to map %s\n", fileInfo.filePath.c_str());
			continue;
		}

		PBYTE pbSearchBegin = nullptr;
		DWORD dwSearchSize = 0;
		if (!TryGetTextSearchRegion(rgScratchBuffer.data(), fileSize, fileInfo.machineType, &pbSearchBegin, &dwSearchSize))
		{
			wprintf(L"Failed to get .text section of %s\n", fileInfo.filePath.c_str());
			continue;
		}

		slot.module->CheckPatterns(
			rgScratchBuffer.data(), fileSize, pbSearchBegin, dwSearchSize, fileInfo.machineType, slot.matches);
		slot.module->PostProcess(fileInfo, slot.matches);
	}
}

void CPatternCheckerSuite::WriteJsonReport(const std::wstring& resultBaseName, double elapsedTime)
{
	EnsureWorkerResultsDirectory();

	rapidjson::Document doc;
	doc.SetObject();
	auto& alloc = doc.GetAllocator();

	rapidjson::Value modulesObject(rapidjson::kObjectType);
	for (const auto& [moduleName, module] : m_modules)
	{
		rapidjson::Value moduleObject(rapidjson::kObjectType);

		rapidjson::Value amd64Versions(rapidjson::kObjectType);
		rapidjson::Value arm64Versions(rapidjson::kObjectType);
		bool bHasAmd64 = false;
		bool bHasArm64 = false;

		std::set<FileInfo, FileInfoComparator> sortedFileInfos;
		for (const auto& info : module->m_matches | std::views::keys)
		{
			if (info.machineType == IMAGE_FILE_MACHINE_AMD64
				|| info.machineType == IMAGE_FILE_MACHINE_ARM64)
			{
				sortedFileInfos.insert(info);
			}
		}

		for (const FileInfo& info : sortedFileInfos)
		{
			auto it = module->m_matches.find(info);
			if (it == module->m_matches.end())
				continue;

			const char* pszArchKey = MachineTypeToArchKey(info.machineType);
			if (!pszArchKey)
				continue;

			std::wstring versionW = FileVersionToWorkerVersionString(info.fileVersion);
			std::string version = WideToUtf8(versionW);

			rapidjson::Value statusArray(rapidjson::kArrayType);
			for (const auto& matchInfo : it->second)
			{
				statusArray.PushBack(MatchInfoToWorkerCode(matchInfo), alloc);
			}

			rapidjson::Value versionKey(version.c_str(), (rapidjson::SizeType)version.size(), alloc);

			if (info.machineType == IMAGE_FILE_MACHINE_AMD64)
			{
				amd64Versions.AddMember(versionKey, statusArray, alloc);
				bHasAmd64 = true;
			}
			else if (info.machineType == IMAGE_FILE_MACHINE_ARM64)
			{
				arm64Versions.AddMember(versionKey, statusArray, alloc);
				bHasArm64 = true;
			}
		}

		if (!bHasAmd64 && !bHasArm64)
		{
			continue;
		}

		if (bHasAmd64)
		{
			moduleObject.AddMember("amd64", amd64Versions, alloc);
		}

		if (bHasArm64)
		{
			moduleObject.AddMember("arm64", arm64Versions, alloc);
		}

		rapidjson::Value legendArray(rapidjson::kArrayType);
		for (const CPatternCheckerSuiteModule_Base::ElementDef& elementDef : module->GetElementDefs())
		{
			std::string longNameUtf8 = WideToUtf8(elementDef.m_longName);
			legendArray.PushBack(rapidjson::Value(longNameUtf8.c_str(), (rapidjson::SizeType)longNameUtf8.size(), alloc), alloc);
		}
		moduleObject.AddMember("legend", legendArray, alloc);

		std::string moduleNameUtf8 = WideToUtf8(moduleName);
		rapidjson::Value moduleKey(moduleNameUtf8.c_str(), (rapidjson::SizeType)moduleNameUtf8.size(), alloc);
		modulesObject.AddMember(moduleKey, moduleObject, alloc);
	}
	doc.AddMember("modules", modulesObject, alloc);

	doc.AddMember("elapsedTimeSeconds", elapsedTime, alloc);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer writer(buffer);
	doc.Accept(writer);

	std::wstring jsonPath = GetWorkerResultsPath(resultBaseName, L".json");

	/*FILE* fp = _wfopen(jsonPath.c_str(), L"wb");
	if (!fp)
		return;*/

	wil::unique_file shFile;
	if (_wfopen_s(&shFile, jsonPath.c_str(), L"w") != 0)
		return;

	fwrite(buffer.GetString(), 1, buffer.GetSize(), shFile.get());
}

void CPatternCheckerSuite::WriteHtmlReport(const std::wstring& resultBaseName)
{
	std::wstringstream md;

	md << L"<!DOCTYPE html>\n";
	md << L"<html lang='ja'>\n";

	md << L"<head>\n";
	md << L"<meta charset='UTF-8'>\n";
	md << L"<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n";
	md << L"<title>パターンテスト結果</title>\n";
	md << L"<link rel='stylesheet' href='styles.css'>\n";
	md << L"</head>\n";

	md << L"<body>\n\n";

	md << L"<h1>結果</h1>\n\n";

	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	time_t nowTime = std::chrono::system_clock::to_time_t(now);
	tm tm;
	localtime_s(&tm, &nowTime);
	md << L"<p>日付: " << std::put_time(&tm, L"%Y/%m/%d %H:%M:%S") << L"</p>\n\n";

	for (const auto& [moduleName, module] : m_modules)
	{
		const std::span<const CPatternCheckerSuiteModule_Base::ElementDef>& elementDefs = module->GetElementDefs();

		md << L"<h2>" << moduleName << L"</h2>\n\n";

		int width = 60; // バージョン
		width += std::max(10, (int)elementDefs.size()) * 16; // 各要素

		md << L"<div style='column-width: " << width << L"px;'>\n";

		md << L"<h3>x64 の一致表</h3>\n\n";
		PrintForModuleAndMachineType(module, md, IMAGE_FILE_MACHINE_AMD64);

		md << L"<h3>ARM64 の一致表</h3>\n\n";
		PrintForModuleAndMachineType(module, md, IMAGE_FILE_MACHINE_ARM64);

		md << L"</div>\n";

		md << L"<h3>解説</h3>\n\n";
		md << L"<ul>\n";
		for (const CPatternCheckerSuiteModule_Base::ElementDef& elementDef : elementDefs)
		{
			md << L"<li>" << elementDef.m_shortName << L": " << elementDef.m_longName << L"</li>\n";
		}
		md << L"</ul>\n";
	}

	md << L"\n";
	md << L"<h3>解説</h3>\n\n";
	md << L"<ul>\n";
	md << L"<li>✕: <font color='#FF0000'>一致なし</font></li>\n";
	md << L"<li>〇: <font color='#00FF00'>一致あり</font>（パターン番号）</li>\n";
	md << L"<li>△: <font color='#FFFF00'>複数一致あり</font>（パターン番号 - 一致数）</li>\n";
	md << L"</ul>\n";

	md << L"</body>\n";
	md << L"</html>\n";

	EnsureWorkerResultsDirectory();

	std::wstring htmlPath = GetWorkerResultsPath(resultBaseName, L".html");
	std::ofstream ofs(htmlPath, std::ios::binary);

	char smarker[3] = { char(0xEF), char(0xBB), char(0xBF) };
	ofs.write(smarker, 3);

	ofs << WideToUtf8(md.str());
}

void CPatternCheckerSuite::PrintForModuleAndMachineType(const std::shared_ptr<CPatternCheckerSuiteModule_Base>& module, std::wstringstream& md, WORD machineType)
{
	md << L"<table>\n";
	md << L"<thead>\n";
	md << L"<tr>\n";
	md << L"<th>バージョン</th>\n";
	for (const CPatternCheckerSuiteModule_Base::ElementDef& elementDef : module->GetElementDefs())
	{
		md << L"<th class='vertical-text' title='" << elementDef.m_longName << L"'>" << elementDef.m_shortName << L"</th>\n";
	}
	md << L"</tr>\n";
	md << L"</thead>\n";

	std::set<FileInfo, FileInfoComparator> sortedFileInfos;
	for (const auto& info : module->m_matches | std::views::keys)
	{
		if (info.machineType != machineType)
		{
			continue;
		}

		sortedFileInfos.insert(info);
	}

	md << L"<tbody>\n";

	for (const FileInfo& info : sortedFileInfos)
	{
		const std::vector<CPatternCheckerSuiteModule_Base::PatternMatchInfo>& matches = module->m_matches[info];

		md << L"<tr>\n";

		DWORD ls = (info.fileVersion >> 0) & 0xFFFFFFFF;
		DWORD ms = (info.fileVersion >> 32) & 0xFFFFFFFF;

		WCHAR szVersion[64];
		swprintf_s(szVersion, L"%d.%d", HIWORD(ls), LOWORD(ls));

		md << L"<td>" << szVersion << L"</td>\n";

		for (const CPatternCheckerSuiteModule_Base::PatternMatchInfo& matchInfo : matches)
		{
			switch (matchInfo.numMatches)
			{
				case 0:
					md << L"<td class='no-match'></td>\n";
					break;
				case 1:
					md << L"<td class='single-match'>";
					if (matchInfo.usingPattern != 0)
						md << L"<span class='little-top-right'>" << matchInfo.usingPattern << L"</span>";
					md << L"</td>\n";
					break;
				case -1:
					md << L"<td class='ignored-match'></td>\n";
					break;
				default:
					md << L"<td class='multiple-match'>";
					if (matchInfo.usingPattern != 0)
						md << L"<span class='little-top-right'>" << matchInfo.usingPattern << L"</span>";
					md << matchInfo.numMatches;
					md << L"</td>\n";
					break;
			}
		}

		md << L"</tr>\n";
	}

	md << L"</tbody>\n";
	md << L"</table>\n\n";
}

int wmain(int argc, wchar_t* argv[])
{
	if (!EnsureWorkerResultsDirectory())
	{
		fwprintf(stderr, L"Failed to create WorkerResults directory.\n");
		return 1;
	}

	std::unique_ptr<CPatternCheckerSuite> suite = std::make_unique<CPatternCheckerSuite>();

	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_Explorer>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_InputSwitch>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_StartTileData>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_TwinUIPCShell>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_UxTheme>());

	CLI::App app("ep_winbin_test_worker");

	// Shared / parsed state
	std::string fullResultBaseNameUtf8;
	std::vector<std::string> fullDirectoriesUtf8;

	std::string incrementalResultBaseNameUtf8;
	std::string incrementalInputListPathUtf8;

	// Explicit subcommands
	CLI::App* fullCmd = app.add_subcommand("full", "Run full scan over one or more directories and produce JSON + HTML.");
	fullCmd->add_option("-d,--dir", fullDirectoriesUtf8, "Directory to scan. May be repeated. Defaults to BinaryCache in current directory.")
		->default_val(std::string("BinaryCache"));
	fullCmd->add_option("-r,--result-base", fullResultBaseNameUtf8, "Result base name. Default: result-<ISO8601 UTC timestamp>.");

	CLI::App* incrementalCmd = app.add_subcommand("incremental", "Run scan over the files listed in a newline-delimited input list and produce JSON only.");
	incrementalCmd->add_option("-i,--input-list", incrementalInputListPathUtf8, "Path to newline-delimited file list.")
		->required();
	incrementalCmd->add_option("-r,--result-base", incrementalResultBaseNameUtf8, "Result base name. Default: result-<ISO8601 UTC timestamp>.");

	std::vector<std::string> narrowArgs;
	narrowArgs.reserve((size_t)argc);
	for (int i = 0; i < argc; ++i)
	{
		narrowArgs.push_back(WideToUtf8(argv[i]));
	}

	std::vector<char*> narrowArgv;
	narrowArgv.reserve((size_t)argc);
	for (std::string& s : narrowArgs)
	{
		narrowArgv.push_back(s.data());
	}

	try
	{
		app.parse(argc, narrowArgv.data());
	}
	catch (const CLI::ParseError& e)
	{
		return app.exit(e);
	}

	// Default behavior: no args / no subcommand -> full mode
	if (argc == 1 || app.get_subcommands().empty() || *fullCmd)
	{
		std::wstring resultBaseName =
			fullResultBaseNameUtf8.empty()
				? MakeDefaultResultBaseNameUtc()
				: Utf8ToWide(fullResultBaseNameUtf8);

		std::vector<std::wstring> rgDirectories;
		if (fullDirectoriesUtf8.empty())
		{
			rgDirectories.push_back(L"BinaryCache");
		}
		else
		{
			rgDirectories.reserve(fullDirectoriesUtf8.size());
			for (const std::string& dir : fullDirectoriesUtf8)
			{
				rgDirectories.push_back(Utf8ToWide(dir));
			}
		}

		suite->RunFull(rgDirectories, resultBaseName, true);
	}
	else if (*incrementalCmd)
	{
		std::wstring resultBaseName = Utf8ToWide(incrementalResultBaseNameUtf8);
		std::wstring inputListPath = Utf8ToWide(incrementalInputListPathUtf8);

		std::vector<std::wstring> rgFiles;
		if (!ReadUtf8Lines(inputListPath, &rgFiles))
		{
			fwprintf(stderr, L"Failed to read input list: %s\n", inputListPath.c_str());
			return 2;
		}

		suite->RunSpecificFiles(rgFiles, resultBaseName);
	}
	else
	{
		fwprintf(stderr, L"Unexpected mode state.\n");
		return 2;
	}

	if (suite->GetProcessedFileCount() == 0)
	{
		fwprintf(stderr, L"No binaries processed.\n");
		return 3;
	}

	return 0;
}

/*int main(int argc, char* argv[])
{
	LARGE_INTEGER startTime;
	QueryPerformanceCounter(&startTime);

	std::unique_ptr<CPatternCheckerSuite> suite = std::make_unique<CPatternCheckerSuite>();

	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_StartTileData>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_TwinUIPCShell>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_UxTheme>());
	suite->RegisterModule(std::make_shared<CPatternCheckerSuiteModule_Explorer>());

	std::vector<std::wstring> rgDirectories;
	/*rgDirectories.push_back(L"C:\\Users\\satri\\RE");
	rgDirectories.push_back(L"C:\\Users\\satri\\RE ARM64");
	rgDirectories.push_back(L"D:\\Downloads\\okp0m2");
	rgDirectories.push_back(L"D:\\Downloads\\uxtheme x64");
	rgDirectories.push_back(L"D:\\Downloads\\s4r7vm");
	rgDirectories.push_back(L"D:\\Downloads\\96xum4");
	rgDirectories.push_back(L"D:\\Downloads\\1803-1909 explorers");
	rgDirectories.push_back(L"D:\\Downloads\\second batch twinui pcshell");
	rgDirectories.push_back(L"D:\\Downloads\\dispense starttiledata");#1#
	rgDirectories.push_back(L"C:\\Users\\satri\\Documents\\AppProjects\\ep_winbin_test\\Glue\\bin\\Debug\\BinaryCache");

	suite->RunFull(rgDirectories);

	LARGE_INTEGER endTime;
	QueryPerformanceCounter(&endTime);
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	double elapsedTime = static_cast<double>(endTime.QuadPart - startTime.QuadPart) / static_cast<double>(freq.QuadPart);
	wprintf(L"%.3f seconds\n", elapsedTime);

	return 0;
}*/
