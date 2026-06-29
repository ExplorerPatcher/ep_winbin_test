#include "PatternCheckerSuiteModule_StartTileData.h"

#include "AssemblyUtils.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_StartTileData::ElementDefs[] =
{
	{ L"ASPUVIA", L"AddStartPinUnpinVerbIfApplicable" },
	{ L"GCDSSCW", L"GetCDSStartCollectionWriter" },
	{ L"CLILR", L"CreateLayoutInitializationLayoutRoot" },
	{ L"MAI_CDSLP", L"MakeAndInitialize_CDSLayoutProvider" },
	{ L"MS_LRI", L"MakeShared_LayoutRootInternal" },
	{ L"MAIOT_W8LMPP", L"MakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor" },
	{ L"LATA1", L"LogAllTilesActivity_Dtor" },
	{ L"FCTEFC", L"FindCollectionTypesEntryForCollection" },
};

CPatternCheckerSuiteModule_StartTileData::CPatternCheckerSuiteModule_StartTileData()
	: CPatternCheckerSuiteModule_Base(L"StartTileData.dll", ElementDefs)
{
}

#define FIND_PATTERN_WITH_GAP(pFile, dwSize, pat1, msk1, siz1, gap1and2, pat2, msk2, siz2, postprocess, dest, numMatches) \
	do \
	{ \
		PBYTE pCurrent = (pFile); \
		while (pCurrent + (siz1) + (gap1and2) + (siz2) < (pFile) + (dwSize)) \
		{ \
			PBYTE matchLocal = (PBYTE)FindPattern( \
				pCurrent, \
				(SIZE_T)(dwSize) - (SIZE_T)(pCurrent - (SIZE_T)(pFile)), \
				(pat1), \
				(msk1), \
				nullptr \
			); \
			if (!matchLocal) \
			{ \
				break; /* We tried our best, but we found nothing... */ \
			} \
 			\
			/* Possible match, shift to continuation search start */ \
			pCurrent = matchLocal + (siz1); \
 			\
			if (!(pCurrent + (gap1and2) + (siz2) < (pFile) + (dwSize))) \
			{ \
				break; /* Not enough space for continuation */ \
			} \
 			\
			/* Check continuation */ \
			PBYTE matchContinuationTest = (PBYTE)FindPattern( \
				pCurrent, \
				(gap1and2) + (siz2), \
				(pat2), \
				(msk2), \
				nullptr \
			); \
			if (!matchContinuationTest) \
			{ \
				continue; /* Not this one, continue at first pattern + pattern size */ \
			} \
 			\
			matchLocal = (postprocess)(matchLocal); \
			if (!matchLocal) \
			{ \
				continue; /* Not this one, continue at first pattern + pattern size */ \
			} \
 			\
			*(dest) = matchLocal; \
			/* break; /* Got it! */ \
 			\
			/* Test further (suite only!) */ \
			++*(numMatches); \
			pCurrent = matchContinuationTest + (siz2); \
		} \
	} \
	while (false)

#define FIND_PATTERN_WITH_GAP_4_(pFile, dwSize, pat1, msk1, siz1, gap1and2, pat2, msk2, siz2, postprocess, dest, numMatches) \
	do \
	{ \
		PBYTE pCurrent = (pFile); \
		while (pCurrent + (siz1) + (gap1and2) + (siz2) < (pFile) + (dwSize)) \
		{ \
			PBYTE matchLocal = (PBYTE)FindPattern_4_( \
				pCurrent, \
				(SIZE_T)(dwSize) - (SIZE_T)(pCurrent - (SIZE_T)(pFile)), \
				(pat1), \
				(msk1), \
				nullptr \
			); \
			if (!matchLocal) \
			{ \
				break; /* We tried our best, but we found nothing... */ \
			} \
 			\
			/* Possible match, shift to continuation search start */ \
			pCurrent = matchLocal + (siz1); \
 			\
			if (!(pCurrent + (gap1and2) + (siz2) < (pFile) + (dwSize))) \
			{ \
				break; /* Not enough space for continuation */ \
			} \
 			\
			/* Check continuation */ \
			PBYTE matchContinuationTest = (PBYTE)FindPattern_4_( \
				pCurrent, \
				(gap1and2) + (siz2), \
				(pat2), \
				(msk2), \
				nullptr \
			); \
			if (!matchContinuationTest) \
			{ \
				continue; /* Not this one, continue at first pattern + pattern size */ \
			} \
 			\
			matchLocal = (postprocess)(matchLocal); \
			if (!matchLocal) \
			{ \
				continue; /* Not this one, continue at first pattern + pattern size */ \
			} \
 			\
			*(dest) = matchLocal; \
			/* break; /* Got it! */ \
 			\
			/* Test further (suite only!) */ \
			++*(numMatches); \
			pCurrent = matchContinuationTest + (siz2); \
		} \
	} \
	while (false)

void CPatternCheckerSuiteModule_StartTileData::CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	INIT_MATCH_INFO_VARS(AddStartPinUnpinVerbIfApplicable);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		/*matchAddStartPinUnpinVerbIfApplicable = (PBYTE)FindPattern(
            pFile,
            dwSize,
            "\x48\x89\x00\x24\x00\x4C\x8B\x00\x4C\x8B\x44\x24\x00\x49\x8B\x00\x00\x8B\x00\xE8",
            "xx?x?xx?xxxx?xx??x?x",
            &numMatchesAddStartPinUnpinVerbIfApplicable
        );*/
		SIZE_T offset = (SIZE_T)pFile;
		while (true)
		{
			// 48 89 ?? 24 ?? 4C 8B ?? 4C 8B 44 24 ?? 49 8B ?? ?? 8B ?? E8 ?? ?? ?? ??
			//                                                             ^^^^^^^^^^^
			matchAddStartPinUnpinVerbIfApplicable = (PBYTE)FindPattern(
				(PVOID)offset,
				dwSize - (DWORD)(offset - (SIZE_T)pFile),
				"\x48\x89\x00\x24\x00\x4C\x8B\x00\x4C\x8B\x44\x24\x00\x49\x8B\x00\x00\x8B\x00\xE8",
				"xx?x?xx?xxxx?xx??x?x",
				nullptr //&numMatchesAddStartPinUnpinVerbIfApplicable
			);
			if (!matchAddStartPinUnpinVerbIfApplicable)
			{
				// We tried our best, but we found nothing...
				break;
			}

			// Possible match, prepare the start offset for the next search
			offset += ((SIZE_T)matchAddStartPinUnpinVerbIfApplicable - offset) + 24 /*first pattern size*/;

			// Check the referred function's preamble to see if this is what we're looking for
			matchAddStartPinUnpinVerbIfApplicable += 19;
			matchAddStartPinUnpinVerbIfApplicable += 5 + *(int*)(matchAddStartPinUnpinVerbIfApplicable + 1);

			// 41 54 41 55 41 56 41 57 48
			PBYTE matchPreambleTest = (PBYTE)FindPattern(
				matchAddStartPinUnpinVerbIfApplicable,
				9 /*second pattern size*/ + 8 /*should start within these first bytes*/,
				"\x41\x54\x41\x55\x41\x56\x41\x57\x48",
				"xxxxxxxxx",
				&numMatchesAddStartPinUnpinVerbIfApplicable
			);

			if (matchPreambleTest)
			{
				// Got it!
				break;
			}
		}
	}
	else
	{
		// 40 F9 E3 03 15 AA ?? ?? 40 F9 E1 03 ?? AA E0 03 ?? AA ?? ?? ?? ?? E3 03 00 2A // NI, GE
		//                                                       ^^^^^^^^^^^
		// Ref: WindowsInternal::Shell::UnifiedTile::Private::UnifiedTilePinUnpinVerbProvider::GetVerbs()
		usingPatternAddStartPinUnpinVerbIfApplicable = 1;
		matchAddStartPinUnpinVerbIfApplicable = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x40\xF9\xE3\x03\x15\xAA\x00\x00\x40\xF9\xE1\x03\x00\xAA\xE0\x03\x00\xAA\x00\x00\x00\x00\xE3\x03\x00\x2A",
			"xxxxxx??xxxx?xxx?x????xxxx",
			&numMatchesAddStartPinUnpinVerbIfApplicable
		);
		if (matchAddStartPinUnpinVerbIfApplicable)
		{
			matchAddStartPinUnpinVerbIfApplicable += 18;
			matchAddStartPinUnpinVerbIfApplicable = (PBYTE)ARM64_FollowBL((DWORD*)matchAddStartPinUnpinVerbIfApplicable);
		}
		else
		{
			// E4 8A 40 A9 E3 03 ?? AA E1 03 ?? AA E0 03 ?? AA ?? ?? ?? ?? ?? ?? ?? F9 E3 03 00 2A // BR
			//                                                 ^^^^^^^^^^^
			// Ref: WindowsInternal::Shell::UnifiedTile::Private::UnifiedTilePinUnpinVerbProvider::GetVerbs()
			usingPatternAddStartPinUnpinVerbIfApplicable = 2;
			matchAddStartPinUnpinVerbIfApplicable = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\xE4\x8A\x40\xA9\xE3\x03\x00\xAA\xE1\x03\x00\xAA\xE0\x03\x00\xAA\x00\x00\x00\x00\x00\x00\x00\xF9\xE3\x03\x00\x2A",
				"xxxxxx?xxx?xxx?x???????xxxxx",
				&numMatchesAddStartPinUnpinVerbIfApplicable
			);
			if (matchAddStartPinUnpinVerbIfApplicable)
			{
				matchAddStartPinUnpinVerbIfApplicable += 16;
				matchAddStartPinUnpinVerbIfApplicable = (PBYTE)ARM64_FollowBL((DWORD*)matchAddStartPinUnpinVerbIfApplicable);
			}
		}
	}
	PUBLISH_MATCH_INFO(AddStartPinUnpinVerbIfApplicable);

	// === BEGIN 26xxx.8474 BREAKAGE FIX ===

	// Tested versions:
	// x64:
	// - 1709: 16299.1992
	// - 1803: 17134.1967
	// - 1809: 17763.8639
	// - 1903: 18362.1766
	// - 2004: 19041.7181
	// x64 & ARM64:
	// - 21H2: 22000.2652
	// - 22H2: 22621.7208
	// - 24H2: 26100.8697
	// - 26H1: 28000.2315
	// - Canary: 29613.1000

	// Microsoft::WRL::Details::MakeAndInitialize<ctc::CDSStartCollectionWriter,ctc::ICollectionWriter,std::wstring &,bool,std::shared_ptr<ctc::CollectionContext> const &>()
	INIT_MATCH_INFO_VARS(GetCDSStartCollectionWriter); // GCDSSCW
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// - GetCDSStartCollectionWriter() non-inlined (16299, 26100 ~)
		// 48 8B D7 E8 ?? ?? ?? ?? 8B D8 48 8B CF E8 ?? ?? ?? ?? 8B C3
		//             ^^^^^^^^^^^
		// Ref: ctc::GetCDSStartCollectionWriter()
		usingPatternGetCDSStartCollectionWriter = 1;
		matchGetCDSStartCollectionWriter = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8B\xD7\xE8\x00\x00\x00\x00\x8B\xD8\x48\x8B\xCF\xE8\x00\x00\x00\x00\x8B\xC3",
			"xxxx????xxxxxx????xx",
			&numMatchesGetCDSStartCollectionWriter
		);
		if (matchGetCDSStartCollectionWriter)
		{
			matchGetCDSStartCollectionWriter += 3;
			matchGetCDSStartCollectionWriter += 5 + *(int*)(matchGetCDSStartCollectionWriter + 1);
		}
		else
		{
			// - GetCDSStartCollectionWriter() inlined (17134 ~ 22621)
			// E8 ?? ?? ?? ?? 8B F0 49 8B CE E8 ?? ?? ?? ?? 48 8B 4D 5F
			//    ^^^^^^^^^^^ . Pattern begins here
			// Ref: ctc::StartTileGridCollectionInitializer::CreateStartCollectionPipeline()
			usingPatternGetCDSStartCollectionWriter = 2;
			matchGetCDSStartCollectionWriter = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x8B\xF0\x49\x8B\xCE\xE8\x00\x00\x00\x00\x48\x8B\x4D\x5F",
				"xxxxxx????xxxx",
				&numMatchesGetCDSStartCollectionWriter
			);
			if (matchGetCDSStartCollectionWriter)
			{
				matchGetCDSStartCollectionWriter -= 5;
				if (matchGetCDSStartCollectionWriter >= pFile && *matchGetCDSStartCollectionWriter == 0xE8)
				{
					matchGetCDSStartCollectionWriter += 5 + *(int*)(matchGetCDSStartCollectionWriter + 1);
				}
				else
				{
					matchGetCDSStartCollectionWriter = nullptr;
					numMatchesGetCDSStartCollectionWriter = 0;
				}
			}
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// - GetCDSStartCollectionWriter() non-inlined (26100 ~)
		// E1 03 13 AA ?? ?? ?? ?? F4 03 00 2A E0 03 13 AA
		//             ^^^^^^^^^^^
		// Ref: ctc::GetCDSStartCollectionWriter()
		usingPatternGetCDSStartCollectionWriter = 1;
		matchGetCDSStartCollectionWriter = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\xE1\x03\x13\xAA\x00\x00\x00\x00\xF4\x03\x00\x2A\xE0\x03\x13\xAA",
			"xxxx????xxxxxxxx",
			&numMatchesGetCDSStartCollectionWriter
		);
		if (matchGetCDSStartCollectionWriter)
		{
			matchGetCDSStartCollectionWriter += 4;
			matchGetCDSStartCollectionWriter = (PBYTE)ARM64_FollowBL((DWORD*)matchGetCDSStartCollectionWriter);
		}
		else
		{
			// - GetCDSStartCollectionWriter() inlined (20348 ~ 25398)
			// ?? 42 00 91 ?? ?? ?? ?? ?? 03 00 2A ... ?? 02 00 F9 28 00 80 52
			//             ^^^^^^^^^^^
			// Ref: ctc::StartTileGridCollectionInitializer::CreateStartCollectionPipeline()
			usingPatternGetCDSStartCollectionWriter = 2;
			FIND_PATTERN_WITH_GAP( // todo _4_
				pFile, dwSize,

				"\x42\x00\x91\x00\x00\x00\x00\x00\x03\x00\x2A",
				"xxx?????xxx",
				11,

				49,

				"\x02\x00\xF9\x28\x00\x80\x52",
				"xxxxxxx",
				7,

				[&](PBYTE matchCandidate) -> PBYTE
				{
					matchCandidate += 3;
					return (PBYTE)ARM64_FollowBL((DWORD*)matchCandidate);
				},

				&matchGetCDSStartCollectionWriter,
				&numMatchesGetCDSStartCollectionWriter
			);
		}
	}
	PUBLISH_MATCH_INFO(GetCDSStartCollectionWriter);

	// ctc::Internal::LayoutRoot::CreateLayoutInitializationLayoutRoot()
	INIT_MATCH_INFO_VARS(CreateLayoutInitializationLayoutRoot); // CLILR
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 16299 ~
		// 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 48 8B ?? 48 89 ?? ?? 48
		//                ^^^^^^^^^^^
		// Ref: ctc::DefaultLayoutParser::ParseStartLayouts()
		matchCreateLayoutInitializationLayoutRoot = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8D\x4D\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x4D\x00\xE8\x00\x00\x00\x00\x48\x8B\x00\x48\x89\x00\x00\x48",
			"xxx?x????xxxx?x????xx?xx??x",
			&numMatchesCreateLayoutInitializationLayoutRoot
		);
		if (matchCreateLayoutInitializationLayoutRoot)
		{
			matchCreateLayoutInitializationLayoutRoot += 4;
			matchCreateLayoutInitializationLayoutRoot += 5 + *(int*)(matchCreateLayoutInitializationLayoutRoot + 1);
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// ?? 42 03 91 ?? E3 00 91 ?? ?? ?? ?? 1F 20 03 D5 A0 63 00 91
		//                         ^^^^^^^^^^^
		// Ref: ctc::DefaultLayoutParser::ParseStartLayouts()
		matchCreateLayoutInitializationLayoutRoot = (PBYTE)FindPattern_4_(
			pFile + 1, dwSize - 1,
			"\x42\x03\x91\x0\xE3\x00\x91\x0\x0\x0\x0\x1F\x20\x03\xD5\xA0\x63\x00\x91",
			"xxx?xxx????xxxxxxxx",
			&numMatchesCreateLayoutInitializationLayoutRoot
		);
		if (matchCreateLayoutInitializationLayoutRoot)
		{
			matchCreateLayoutInitializationLayoutRoot += 7;
			matchCreateLayoutInitializationLayoutRoot = (PBYTE)ARM64_FollowBL((DWORD*)matchCreateLayoutInitializationLayoutRoot);
		}
	}
	PUBLISH_MATCH_INFO(CreateLayoutInitializationLayoutRoot);

	// Microsoft::WRL::Details::MakeAndInitialize<ctc::CDSLayoutProvider,ctc::IInitialCollectionProvider,unsigned short const (&)[15],std::shared_ptr<ctc::CollectionContext> const &>
	INIT_MATCH_INFO_VARS(MakeAndInitialize_CDSLayoutProvider); // MAI_CDSLP
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 16299 ~
		// 4C 8D 41 08 48 8B CA E8 ?? ?? ?? ?? 85 C0 79 1A
		//                         ^^^^^^^^^^^
		// Ref: ctc::AppendWin8UpgradeTilesPolicy::GetCustomProvider()
		// Warning: a2 is optimized out to be always L"Start.TileGrid"
		matchMakeAndInitialize_CDSLayoutProvider = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x4C\x8D\x41\x08\x48\x8B\xCA\xE8\x00\x00\x00\x00\x85\xC0\x79\x1A",
			"xxxxxxxx????xxxx",
			&numMatchesMakeAndInitialize_CDSLayoutProvider
		);
		if (matchMakeAndInitialize_CDSLayoutProvider)
		{
			matchMakeAndInitialize_CDSLayoutProvider += 7;
			matchMakeAndInitialize_CDSLayoutProvider += 5 + *(int*)(matchMakeAndInitialize_CDSLayoutProvider + 1);
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// 02 20 00 91 E0 03 13 AA ?? ?? ?? ?? E3 03 00 2A
		//                         ^^^^^^^^^^^
		// Ref: ctc::AppendWin8UpgradeTilesPolicy::GetCustomProvider()
		// Warning: a2 is optimized out to be always L"Start.TileGrid"
		matchMakeAndInitialize_CDSLayoutProvider = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\x02\x20\x00\x91\xE0\x03\x13\xAA\x00\x00\x00\x00\xE3\x03\x00\x2A",
			"xxxxxxxx????xxxx",
			&numMatchesMakeAndInitialize_CDSLayoutProvider
		);
		if (matchMakeAndInitialize_CDSLayoutProvider)
		{
			matchMakeAndInitialize_CDSLayoutProvider += 8;
			matchMakeAndInitialize_CDSLayoutProvider = (PBYTE)ARM64_FollowBL((DWORD*)matchMakeAndInitialize_CDSLayoutProvider);
		}
	}
	PUBLISH_MATCH_INFO(MakeAndInitialize_CDSLayoutProvider);

	// std::make_shared<ctc::Internal::LayoutRootInternal,std::shared_ptr<ctc::CollectionContext> &,std::shared_ptr<DataStoreCache::CuratedTileCollectionTransformer::CuratedRoot> >()
	INIT_MATCH_INFO_VARS(MakeShared_LayoutRootInternal); // MS_LRI
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 16299 ~
		// E8 ?? ?? ?? ?? 48 8B D0 ?? 8D ?? 10 E8 ?? ?? ?? ?? 48 8B ?? 24
		//    ^^^^^^^^^^^ . Pattern begins here
		// The 48 8B ?? 24 can be:
		// - 48 8B 4C 24 70          <continuation 1 byte after first pattern + pattern size>
		// - 48 8B 8C 24 80 00 00 00 <continuation 4 bytes ...>
		//               . First pattern + pattern size
		//               ----------- 4 bytes max gap
		// Continued by:
		// 48 85 C9 74 06 E8 ?? ?? ?? ?? 90 48 8B ?? 24
		// Ref: ctc::PreserveLayoutPostProcessor::RuntimeClassInitialize()
		FIND_PATTERN_WITH_GAP(
			pFile, dwSize,

			"\x48\x8B\xD0\x00\x8D\x00\x10\xE8\x00\x00\x00\x00\x48\x8B\x00\x24",
			"xxx?x?xx????xx?x",
			16,

			4,

			"\x48\x85\xC9\x74\x06\xE8\x00\x00\x00\x00\x90\x48\x8B\x00\x24",
			"xxxxxx????xxx?x",
			15,

			[&](PBYTE matchCandidate) -> PBYTE
			{
				matchCandidate -= 5;
				if (matchCandidate >= pFile && *matchCandidate == 0xE8)
				{
					return matchCandidate + 5 + *(int*)(matchCandidate + 1);
				}
				else
				{
					return nullptr;
				}
			},

			&matchMakeShared_LayoutRootInternal,
			&numMatchesMakeShared_LayoutRootInternal
		);
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// ?? 82 00 91 ?? ?? ?? ?? E1 03 00 AA ?? 42 00 91
		//             ^^^^^^^^^^^
		// Ref: ctc::PreserveLayoutPostProcessor::RuntimeClassInitialize()
		matchMakeShared_LayoutRootInternal = (PBYTE)FindPattern_4_(
			pFile + 1, dwSize - 1,
			"\x82\x00\x91\x00\x00\x00\x00\xE1\x03\x00\xAA\x00\x42\x00\x91",
			"xxx????xxxx?xxx",
			&numMatchesMakeShared_LayoutRootInternal
		);
		if (matchMakeShared_LayoutRootInternal)
		{
			matchMakeShared_LayoutRootInternal += 3;
			matchMakeShared_LayoutRootInternal = (PBYTE)ARM64_FollowBL((DWORD*)matchMakeShared_LayoutRootInternal);
		}
		else
		{
			// Note: 26100+ make_shared is inlined here

			// 00 2E 80 D2 ?? ?? ?? ?? F3 03 00 AA B3 0B 00 F9 ?? ?? ?? ?? ?? ?? ?? ?? E9 03 00 B2 A2 83 01 91 68 26 00 A9 A7 ?? C0 ?? ?? 82 00 91 60 42 00 91 BF 7F ?? A9 A7 1B 80 3D ?? ?? ?? ?? 1F 20 03 D5 68 42 00 91 A1 43 00 91 A8 4F 01 A9 ?? 42 00 91 ?? ?? ?? ?? A0 0F 40 F9
			matchMakeShared_LayoutRootInternal = (PBYTE)FindPattern_4_(
				pFile, dwSize,
				"\x00\x2E\x80\xD2\x00\x00\x00\x00\xF3\x03\x00\xAA\xB3\x0B\x00\xF9\x00\x00\x00\x00\x00\x00\x00\x00\xE9\x03\x00\xB2\xA2\x83\x01\x91\x68\x26\x00\xA9\xA7\x00\xC0\x00\x00\x82\x00\x91\x60\x42\x00\x91\xBF\x7F\x00\xA9\xA7\x1B\x80\x3D\x00\x00\x00\x00\x1F\x20\x03\xD5\x68\x42\x00\x91\xA1\x43\x00\x91\xA8\x4F\x01\xA9\x00\x42\x00\x91\x00\x00\x00\x00\xA0\x0F\x40\xF9",
				"xxxx????xxxxxxxx????????xxxxxxxxxxxxx?x??xxxxxxxxx?xxxxx????xxxxxxxxxxxxxxxx?xxx????xxxx",
				&numMatchesMakeShared_LayoutRootInternal
			);
		}
	}
	PUBLISH_MATCH_INFO(MakeShared_LayoutRootInternal);

	// wil::MakeAndInitializeOrThrow<ctc::Win8LayoutMigrationPostProcessor,HSTRING__ * &,std::shared_ptr<ctc::CollectionContext> const &>()
	INIT_MATCH_INFO_VARS(MakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor); // MAIOT_W8LMPP
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// - ctc::CreateWin8LayoutMigrationPostProcessor() inlined (17134 ~)
		// 4C 8D 41 08 48 8D 55 28 48 8D 4D 30 E8 ?? ?? ?? ?? 48 8B 08 48 ?? ?? 00
		//                                        ^^^^^^^^^^^
		// 48 ?? ?? 00 ... can be:
		// - 48 83 20 00          <continuation 0 bytes after first pattern + pattern size>
		// - 48 C7 00 00 00 00 00 <continuation 3 bytes ...>
		//               . First pattern + pattern size
		//               -------- 3 bytes max gap
		// Continued by:
		// 48 89 4D 18 C7 45 D8 02 00 00 00
		// Ref: ctc::AppendWin8UpgradeTilesPolicy::GetPostProcessors()
		/*FIND_PATTERN_WITH_GAP(
			pFile, dwSize,

			"\x4C\x8D\x41\x08\x48\x8D\x55\x28\x48\x8D\x4D\x30\xE8\x00\x00\x00\x00\x48\x8B\x08\x48\x00\x00\x00",
			"xxxxxxxxxxxxx????xxxx??x",
			24,

			3,

			"\x48\x89\x4D\x18\xC7\x45\xD8\x02\x00\x00\x00",
			"xxxxxxxxxxx",
			11,

			[&](PBYTE matchCandidate) -> PBYTE
			{
				matchCandidate += 12;
				return matchCandidate + 5 + *(int*)(matchCandidate + 1);
			},

			&matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor,
			&numMatchesMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor
		);*/ // This complex 2-step method is not needed
		usingPatternMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor = 1;
		matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x4C\x8D\x41\x08\x48\x8D\x55\x28\x48\x8D\x4D\x30\xE8\x00\x00\x00\x00\x48\x8B\x08\x48\x00\x00\x00",
			"xxxxxxxxxxxxx????xxxx??x",
			&numMatchesMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor
		);
		if (matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor)
		{
			matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor += 12;
			matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor += 5 + *(int*)(matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor + 1);
		}
		else
		{
			// !!! (Please comment this outside the suite, we're not patching 16299 ctc) !!!

			// - ctc::CreateWin8LayoutMigrationPostProcessor() non-inlined (16299)
			// Instead look for Microsoft::WRL::Details::MakeAndInitialize<ctc::Win8LayoutMigrationPostProcessor,ctc::Win8LayoutMigrationPostProcessor,HSTRING__ * &,std::shared_ptr<ctc::CollectionContext> const &>()
			// 4C 8B C3 48 8D 54 24 48 48 8D 4C 24 58 E8 ?? ?? ?? ?? 48 8B 4C 24 38 85 C0
			//                                           ^^^^^^^^^^^
			// Ref: ctc::CreateWin8LayoutMigrationPostProcessor()
			usingPatternMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor = 2;
			matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x4C\x8B\xC3\x48\x8D\x54\x24\x48\x48\x8D\x4C\x24\x58\xE8\x0\x0\x0\x0\x48\x8B\x4C\x24\x38\x85\xC0",
				"xxxxxxxxxxxxxx????xxxxxxx",
				&numMatchesMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor
			);
			if (matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor)
			{
				matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor += 13;
				matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor += 5 + *(int*)(matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor + 1);
			}
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// A1 83 00 91 A0 A3 00 91 A8 13 00 F9 ?? ?? ?? ?? ... (max 16, 21 including masks) ?? 00 80 52
		//                                     ^^^^^^^^^^^
		// Ref: ctc::PreserveLayoutPostProcessor::RuntimeClassInitialize()
		FIND_PATTERN_WITH_GAP(
			pFile, dwSize,

			"\xA1\x83\x00\x91\xA0\xA3\x00\x91\xA8\x13\x00\xF9",
			"xxxxxxxxxxxx",
			12,

			21,

			"\x00\x80\x52",
			"xxx",
			3,

			[&](PBYTE matchCandidate) -> PBYTE
			{
				matchCandidate += 12;
				return (PBYTE)ARM64_FollowBL((DWORD*)matchCandidate);
			},

			&matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor,
			&numMatchesMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor
		);
		/*matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor = (PBYTE)FindPatternBitMask_4_(
			pFile, dwSize,
			"\xA1\x83\x00\x91\xA0\xA3\x00\x91\xA8\x13\x00\xF9\x00\x00\x00\x94",
			"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\xFC",
			16,
			&numMatchesMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor
		);
		if (matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor)
		{
			matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor += 12;
			matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor = (PBYTE)ARM64_FollowBL((DWORD*)matchMakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor);
		}*/
	}
	PUBLISH_MATCH_INFO(MakeAndInitializeOrThrow_Win8LayoutMigrationPostProcessor);

	// CommonStartTelemetry::LogAllTilesActivity::~LogAllTilesActivity()
	INIT_MATCH_INFO_VARS(LogAllTilesActivity_Dtor); // LATA1
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 16299~
		// 48 85 C9 74 06 E8 ?? ?? ?? ?? 90 49 8B ?? E8 ?? ?? ?? ?? 33 C0 48 8B 4D ?? 48 33 CC
		//                                              ^^^^^^^^^^^
		// Ref: ctc::GenericCollectionWriter::WriteCollection()
		matchLogAllTilesActivity_Dtor = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x85\xC9\x74\x06\xE8\x00\x00\x00\x00\x90\x49\x8B\x00\xE8\x00\x00\x00\x00\x33\xC0\x48\x8B\x4D\x00\x48\x33\xCC",
			"xxxxxx????xxx?x????xxxxx?xxx",
			&numMatchesLogAllTilesActivity_Dtor
		);
		if (matchLogAllTilesActivity_Dtor)
		{
			matchLogAllTilesActivity_Dtor += 14;
			matchLogAllTilesActivity_Dtor += 5 + *(int*)(matchLogAllTilesActivity_Dtor + 1);
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// ?? ?? 40 F9 60 00 00 B4 ?? ?? ?? ?? 1F 20 03 D5 E0 03 ?? AA ?? ?? ?? ?? 00 00 80 52 FF 43 01 91
		//                                                             ^^^^^^^^^^^
		// Ref: ctc::GenericCollectionWriter::WriteCollection()
		matchLogAllTilesActivity_Dtor = (PBYTE)FindPattern_4_(
			pFile + 2, dwSize - 2,
			"\x40\xF9\x60\x00\x00\xB4\x00\x00\x00\x00\x1F\x20\x03\xD5\xE0\x03\x00\xAA\x00\x00\x00\x00\x00\x00\x80\x52\xFF\x43\x01\x91",
			"xxxxxx????xxxxxx?x????xxxxxxxx",
			&numMatchesLogAllTilesActivity_Dtor
		);
		if (matchLogAllTilesActivity_Dtor)
		{
			matchLogAllTilesActivity_Dtor += 18;
			matchLogAllTilesActivity_Dtor = (PBYTE)ARM64_FollowBL((DWORD*)matchLogAllTilesActivity_Dtor);
		}
	}
	PUBLISH_MATCH_INFO(LogAllTilesActivity_Dtor);

	// ctc::FindCollectionTypesEntryForCollection()
	// Call with L"Start.TileGrid" to get ctc::Create_StartTileGridCollectionInitializer() & ctc::Create_StartTileGridCollection()
	INIT_MATCH_INFO_VARS(FindCollectionTypesEntryForCollection); // FCTEFC
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
#if 0
		// 26100~
		// std::pair construction inlined
		// 48 8D 4D ?? E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ??
		//                                     ^^^^^^^^^^^ STGCInitializer      ^^^^^^^^^^^ STGC
		// Do not include std::string ctor bytes, it was not inlined until 29553 requiring another pattern if we need to cover
		// Ref: WindowsInternal::Shell::UnifiedTile::CuratedTileCollections::`dynamic initializer for 'CollectionTypesMap''
		usingPatternFindCollectionTypesEntryForCollection = 1;
		matchFindCollectionTypesEntryForCollection = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8D\x4D\x00\xE8\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x45\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x45",
			"xxx?x????xxx????xxx?xxx????xxx",
			&numMatchesFindCollectionTypesEntryForCollection
		);
		if (matchFindCollectionTypesEntryForCollection)
		{
			// Process here: +9 and +20
		}
		else
		{
			// 18362~
			// std::pair construction not inlined; STGCInitalizer placed using rsp offset
			// 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 4C 8D 44 24 ??
			//                      ^^^^^^^^^^^ STGCInitializer         ^^^^^^^^^^^ STGC
			// Ref: WindowsInternal::Shell::UnifiedTile::CuratedTileCollections::`dynamic initializer for 'CollectionTypesMap''
			usingPatternFindCollectionTypesEntryForCollection = 2;
			matchFindCollectionTypesEntryForCollection = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x48\x89\x45\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x44\x24\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x44\x24\x00\x4C\x8D\x44\x24",
				"xxx?xxx????xxxx?xxx????xxxx?xxxx",
				&numMatchesFindCollectionTypesEntryForCollection
			);
			if (matchFindCollectionTypesEntryForCollection)
			{
				// Process here: +4 and +16
			}
			else // !!! (Please comment this outside the suite, we're not patching 16299 ctc) !!!
			{
				// 16299~
				// std::pair construction not inlined; STGCInitalizer placed using rbp offset
				// 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 4C 8D 45 ??
				//                      ^^^^^^^^^^^ STGCInitializer         ^^^^^^^^^^^ STGC
				// Ref: WindowsInternal::Shell::UnifiedTile::CuratedTileCollections::`dynamic initializer for 'CollectionTypesMap''
				usingPatternFindCollectionTypesEntryForCollection = 3;
				matchFindCollectionTypesEntryForCollection = (PBYTE)FindPattern(
					pFile, dwSize,
					"\x48\x89\x45\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x45\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x45\x00\x4C\x8D\x45",
					"xxx?xxx????xxx?xxx????xxx?xxx",
					&numMatchesFindCollectionTypesEntryForCollection
				);
				if (matchFindCollectionTypesEntryForCollection)
				{
					// Process here: +4 and +15
				}
			}
		}
#endif

		// 49 8B D6 48 8D 4D ?? E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0
		//                                                 ^^^^^^^^^^^
		// Ref: ctc::CuratedTileCollectionManager::GetCollectionForCollectionName()
		matchFindCollectionTypesEntryForCollection = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x49\x8B\xD6\x48\x8D\x4D\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x85\xC0",
			"xxxxxx?x????xxxx????xxx",
			&numMatchesFindCollectionTypesEntryForCollection
		);
		if (matchFindCollectionTypesEntryForCollection)
		{
			matchFindCollectionTypesEntryForCollection += 15;
			matchFindCollectionTypesEntryForCollection += 5 + *(int*)(matchFindCollectionTypesEntryForCollection + 1);
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// If we're looking for both Create_ functions directly, which are referenced in the dynamic initializer,
		// unfortunately the code in it is too fragile (very dynamic std::string and std::map inlining). So we need to
		// use a more stable method

		// FD 7B ?? A9 FD 03 00 91 ?? 03 00 AA ?? 03 01 AA E1 03 02 AA E0 ?? 00 91 ?? ?? ?? ?? ?? ?? ?? ??
		//                                                                                     ^^^^^^^^^^^
		// Ref: ctc::CuratedTileCollectionManager::GetInitializerForCollectionName()
		matchFindCollectionTypesEntryForCollection = (PBYTE)FindPatternBitMask_4_(
			pFile, dwSize,
			"\xFD\x7B\x00\xA9\xFD\x03\x00\x91\x00\x03\x00\xAA\x00\x03\x01\xAA\xE1\x03\x02\xAA\xE0\x00\x00\x91\x00\x00\x00\x94\x00\x00\x00\x94",
			"\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\x00\x00\x00\xFC\x00\x00\x00\xFC",
			32,
			&numMatchesFindCollectionTypesEntryForCollection
		);
		if (matchFindCollectionTypesEntryForCollection)
		{
			matchFindCollectionTypesEntryForCollection += 28;
			matchFindCollectionTypesEntryForCollection = (PBYTE)ARM64_FollowBL((DWORD*)matchFindCollectionTypesEntryForCollection);
		}
	}
	PUBLISH_MATCH_INFO(FindCollectionTypesEntryForCollection);

	// === END 26xxx.8474 BREAKAGE FIX ===
}

#undef FIND_PATTERN_WITH_GAP

bool CPatternCheckerSuiteModule_StartTileData::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	if (!CPatternCheckerSuiteModule_Base::ShouldIncludeFile(fileInfo))
		return false;

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	return fileInfo.machineType == IMAGE_FILE_MACHINE_ARM64 ? build >= 20000 /*include Iron*/ : build >= 16299;
}

void CPatternCheckerSuiteModule_StartTileData::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	// anything before 22621.2340, mark as don't care (numMatches = -1)
	if (build < 22621 || (build == 22621 && ubr < 2340) || (build >= 25000 && build < 26100))
	{
		int i = 0;
		for (PatternMatchInfo& match : *matches)
		{
			if (i == 0)
			{
				match.numMatches = -1;
			}
			++i;
		}
	}
}