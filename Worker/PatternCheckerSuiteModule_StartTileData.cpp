#include "PatternCheckerSuiteModule_StartTileData.h"

#include "AssemblyUtils.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_StartTileData::ElementDefs[] =
{
	{ L"ASPUVIA", L"AddStartPinUnpinVerbIfApplicable" },
};

CPatternCheckerSuiteModule_StartTileData::CPatternCheckerSuiteModule_StartTileData()
	: CPatternCheckerSuiteModule_Base(L"StartTileData.dll", ElementDefs)
{
}

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
}

void CPatternCheckerSuiteModule_StartTileData::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	// anything before 22621.2340, mark as don't care (numMatches = -1)
	if (build < 22621 || (build == 22621 && ubr < 2340))
	{
		for (PatternMatchInfo& match : *matches)
		{
			match.numMatches = -1;
		}
	}
}
