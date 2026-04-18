#include "PatternCheckerSuiteModule_Explorer.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_Explorer::ElementDefs[] =
{
	{ L"1", L"1号" },
	{ L"2", L"2号" },
	{ L"3", L"3号" },
	{ L"4", L"4号" },
	{ L"5", L"5号" },
	{ L"6", L"6号" },
	{ L"7", L"7号" },
	{ L"8", L"8号" },
	{ L"9", L"9号" },
	{ L"10", L"10号" },
	{ L"11", L"11号" },
	{ L"12", L"12号" },
	{ L"13", L"13号" },
	{ L"14", L"14号" },
	{ L"15", L"15号" },
	{ L"TUCI", L"TrayUI_CreateInstance" },
	// { L"THF", L"TaskbarHasFocus" },
};

CPatternCheckerSuiteModule_Explorer::CPatternCheckerSuiteModule_Explorer()
	: CPatternCheckerSuiteModule_Base(L"EXPLORER.EXE", ElementDefs)
{
}

// ReSharper disable CppEntityAssignedButNoRead
void CPatternCheckerSuiteModule_Explorer::CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	struct WINDOWPOSITIONS;
	struct ITrustedComponentForegroundControl;
	enum RAISEDESKTOPFLAGS : int;

	void* p_c_trayStatic = {};
	bool* p_c_trayStatic_m_bImmersiveShellStarted = {};
	HRESULT (*p_CTray_GetImmersiveShellServiceProvider)(void* _this, IServiceProvider** ppv, bool a3) = {};
	long* p_g_fWinHomeListening = {};
	bool* p_c_trayStatic_m_bTrayThreadStarting = {};
	bool* p_c_trayStatic_m_bExplorerShuttingDownCheck1 = {};
	bool* p_c_trayStatic_m_bExplorerShuttingDownCheck2 = {};
	LRESULT (*p_CTray_QueryUserNotificationState)(void* _this) = {};
	LRESULT (*p_CTray_OnAppCommand)(void* _this, int cmdId) = {};
	int* p_c_trayStatic_m_minimizeFlags = {};
	HWND* p_c_trayStatic_m_hwndShakerRoot = {};
	void (*p_CTray_SaveWindowPositions)(void* _this, UINT flags) = {};
	WINDOWPOSITIONS** p_c_trayStatic_m_savedWindowPos = {};
	HWND* p_v_hwndDesktop = {};
	BOOL* p_g_fInSizeMove = {};
	BOOL* g_fDesktopRaised = {};
	HWND* p_c_trayStatic_m_hwndLastActive = {};
	HRESULT (*p_GetDestinationItemFromDataObjectHelper)(IDataObject* dataObject, REFIID riid, void** ppv) = {};
	ITrustedComponentForegroundControl** p_g_pForegroundControl = {};
	void (*p_CTray__RaiseDesktop)(void* _this, RAISEDESKTOPFLAGS flags) = {};
	void (*p_EnsureTabletButtonThreadRunningIfNeeded)() = {};

	// (a) c_trayStatic
	// (b) c_trayStatic.m_bImmersiveShellStarted
	// (c) CTray::GetImmersiveShellServiceProvider()
	// C6 05 ?? ?? ?? ?? 01 41 B0 01 48 8D 55 F0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??
	// .     ^^^^(b)^^^^                         .        ^^^^(a)^^^^ .  ^^^^(c)^^^^
	// Ref: CTaskBand::Exec()
	INIT_MATCH_INFO_VARS(1);
	match1 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\xC6\x05\x00\x00\x00\x00\x01\x41\xB0\x01\x48\x8D\x55\xF0\x48\x8D\x0D\x00\x00\x00\x00\xE8",
		"xx????xxxxxxxxxxx????x",
		&numMatches1
	);
	if (match1)
	{
		PBYTE match1a = match1 + 14;
		match1a += 7 + *(int*)(match1a + 3);
		p_c_trayStatic = (decltype(p_c_trayStatic))match1a;

		PBYTE match1b = match1;
		match1b += 7 + *(int*)(match1b + 2);
		p_c_trayStatic_m_bImmersiveShellStarted = (decltype(p_c_trayStatic_m_bImmersiveShellStarted))match1b;

		PBYTE match1c = match1 + 21;
		match1c += 5 + *(int*)(match1c + 1);
		p_CTray_GetImmersiveShellServiceProvider = (decltype(p_CTray_GetImmersiveShellServiceProvider))match1c;
	}
	PUBLISH_MATCH_INFO(1);

	// (a) g_fWinHomeListening
	// 8D 43 01 F0 0F B1 1D ?? ?? ?? ?? 85 C0
	//          .           ^^^^(a)^^^^
	// Ref: CTaskBand::MinimizeAllThreadProc()
	INIT_MATCH_INFO_VARS(2);
	match2 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x8D\x43\x01\xF0\x0F\xB1\x1D\x00\x00\x00\x00\x85\xC0",
		"xxxxxxx????xx",
		&numMatches2
	);
	if (match2)
	{
		PBYTE match2a = match2 + 3;
		match2a += 8 + *(int*)(match2a + 4);
		p_g_fWinHomeListening = (decltype(p_g_fWinHomeListening))match2a;
	}
	PUBLISH_MATCH_INFO(2);

	// (a) c_trayStatic.m_bTrayThreadStarting
	// (b) c_trayStatic.m_bExplorerShuttingDownCheck1
	// (c) c_trayStatic.m_bExplorerShuttingDownCheck2
	// Pattern 1: In one go
	// 40 38 35 ?? ?? ?? ?? 75 36 40 38 35 ?? ?? ?? ?? 75 2D 40 38 35 ?? ?? ?? ?? 75 24
	// .        ^^^^(a)^^^^       .        ^^^^(b)^^^^       .        ^^^^(c)^^^^
	// Ref: CTaskBand::_HandleDestroy()
	INIT_MATCH_INFO_VARS(3);
	match3 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x40\x38\x35\x00\x00\x00\x00\x75\x36\x40\x38\x35\x00\x00\x00\x00\x75\x2D\x40\x38\x35\x00\x00\x00\x00\x75\x24",
		"xxx????xxxxx????xxxxx????xx",
		&numMatches3
	);
	if (match3)
	{
		PBYTE match3a = match3;
		match3a += 7 + *(int*)(match3a + 3);
		p_c_trayStatic_m_bTrayThreadStarting = (decltype(p_c_trayStatic_m_bTrayThreadStarting))match3a;

		PBYTE match3b = match3 + 9;
		match3b += 7 + *(int*)(match3b + 3);
		p_c_trayStatic_m_bExplorerShuttingDownCheck1 = (decltype(p_c_trayStatic_m_bExplorerShuttingDownCheck1))match3b;

		PBYTE match3c = match3 + 18;
		match3c += 7 + *(int*)(match3c + 3);
		p_c_trayStatic_m_bExplorerShuttingDownCheck2 = (decltype(p_c_trayStatic_m_bExplorerShuttingDownCheck2))match3c;
	}
	else
	{
		// Pattern 2: Split by a long jump
		// 48 8B F9 48 39 33 74 25 40 38 35 ?? ?? ?? ?? 0F 84 ?? ?? ?? ??
		//                         .        ^^^^(a)^^^^ .     ^^^^(z)^^^^
		// Ref: CTaskBand::_HandleDestroy()
		match3 = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8B\xF9\x48\x39\x33\x74\x25\x40\x38\x35\x00\x00\x00\x00\x0F\x84",
			"xxxxxxxxxxx????xx",
			&numMatches3
		);
		if (match3)
		{
			PBYTE match3a = match3 + 8;
			match3a += 7 + *(int*)(match3a + 3);
			p_c_trayStatic_m_bTrayThreadStarting = (decltype(p_c_trayStatic_m_bTrayThreadStarting))match3a;

			PBYTE match3z = match3 + 15;
			match3z += 6 + *(int*)(match3z + 2); // Follow long jz

			// And then:
			// 40 38 35 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 40 38 35 ?? ?? ?? ?? 0F 85 ?? ?? ?? ??
			// .        ^^^^(b)^^^^                   .        ^^^^(c)^^^^
			match3z = (PBYTE)FindPattern(
				match3z,
				35, // Pattern size, sanity check if that jz leads us to what we want
				"\x40\x38\x35\x00\x00\x00\x00\x0F\x85\x00\x00\x00\x00\x40\x38\x35\x00\x00\x00\x00\x0F\x85",
				"xxx????xx????xxx????xx",
				nullptr
			);
			if (match3z)
			{
				PBYTE match3b = match3z + 0;
				match3b += 7 + *(int*)(match3b + 3);
				p_c_trayStatic_m_bExplorerShuttingDownCheck1 = (decltype(p_c_trayStatic_m_bExplorerShuttingDownCheck1))match3b;

				PBYTE match3c = match3z + 13;
				match3c += 7 + *(int*)(match3c + 3);
				p_c_trayStatic_m_bExplorerShuttingDownCheck2 = (decltype(p_c_trayStatic_m_bExplorerShuttingDownCheck2))match3c;
			}
			else
			{
				numMatches3 = 0;
			}
		}
	}
	PUBLISH_MATCH_INFO(3);

	// CTray::QueryUserNotificationState()
	// Pattern 1:
	// 40 53 48 83 EC 20 83 64 24 ?? ?? 4C 8D 44 24
	// Ref: Itself
	INIT_MATCH_INFO_VARS(4);
	usingPattern4 = 1;
	match4 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x40\x53\x48\x83\xEC\x20\x83\x64\x24\x00\x00\x4C\x8D\x44\x24",
		"xxxxxxxxx??xxxx",
		&numMatches4
	);
	if (match4)
	{
		p_CTray_QueryUserNotificationState = (decltype(p_CTray_QueryUserNotificationState))match4;
	}
	else
	{
		// Pattern 2:
		// 48 89 5C 24 08 57 48 83 EC 20 83 64 24 38 00 4C 8D 44 24 38
		// Ref: Itself
		usingPattern4 = 2;
		match4 = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x83\x64\x24\x38\x00\x4C\x8D\x44\x24\x38",
			"xxxxxxxxxxxxxxxxxxxx",
			&numMatches4
		);
	}
	PUBLISH_MATCH_INFO(4);

	// (a) CTray::OnAppCommand()
	// 48 C1 ?? 10 81 ?? FF 0F 00 00 8B ?? 48 8B 89 ?? ?? ?? ?? E8 ?? ?? ?? ??
	//                                                          .  ^^^^(a)^^^^
	// Ref: CTaskBand::_HandleShellHook()
	INIT_MATCH_INFO_VARS(5);
	match5 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\xC1\x00\x10\x81\x00\xFF\x0F\x00\x00\x8B\x00\x48\x8B\x89\x00\x00\x00\x00\xE8",
		"xx?xx?xxxxx?xxx????x",
		&numMatches5
	);
	if (match5)
	{
		PBYTE match5a = match5 + 19;
		match5a += 5 + *(int*)(match5a + 1);
		p_CTray_OnAppCommand = (decltype(p_CTray_OnAppCommand))match5a;
	}
	PUBLISH_MATCH_INFO(5);

	// (a) c_trayStatic.m_minimizeFlags
	// (b) c_trayStatic.m_hwndShakerRoot
	// 48 89 47 ?? 83 4F ?? 02
	//          (b)      (a)
	// Ref: CTray::_ShakeTriggered()
	INIT_MATCH_INFO_VARS(6);
	match6 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\x89\x47\x00\x83\x4F\x00\x02",
		"xxx?xx?x",
		&numMatches6
	);
	if (match6)
	{
		p_c_trayStatic_m_minimizeFlags = (decltype(p_c_trayStatic_m_minimizeFlags))((PBYTE)p_c_trayStatic + *(char*)(match6 + 6));
		p_c_trayStatic_m_hwndShakerRoot = (decltype(p_c_trayStatic_m_hwndShakerRoot))((PBYTE)p_c_trayStatic + *(char*)(match6 + 3));
	}
	PUBLISH_MATCH_INFO(6);

	// (a) CTray::SaveWindowPositions() !! NB: Not working in 1809
	// 81 ?? 94 01 00 00 0F 44 D0 E8 ?? ?? ?? ??
	//                            .  ^^^^(a)^^^^
	// E8 ?? ?? ?? ?? 48 C7 44 24 20 01 00 00 00 45 33 C9 33 D2 45 8D 41 03 48 8B CF E8
	// .  ^^^^(a)^^^^ > (Start from here)
	// Ref: CTray::Command()
	INIT_MATCH_INFO_VARS(7);
	match7 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\xC7\x44\x24\x20\x01\x00\x00\x00\x45\x33\xC9\x33\xD2\x45\x8D\x41\x03\x48\x8B\xCF\xE8",
		"xxxxxxxxxxxxxxxxxxxxxx",
		&numMatches7
	);
	if (match7)
	{
		PBYTE match7a = match7 - 5;
		if (*match7a == 0xE8) // call
		{
			match7a += 5 + *(int*)(match7a + 1);
			p_CTray_SaveWindowPositions = (decltype(p_CTray_SaveWindowPositions))match7a;
		}
	}
	PUBLISH_MATCH_INFO(7);

	// (a) c_trayStatic.m_savedWindowPos
	// 48 8B 83 ?? ?? ?? ?? 48 83 78 08 00
	//          ^^^^(a)^^^^
	// Ref: CTray::SaveWindowPositions()
	INIT_MATCH_INFO_VARS(8);
	if (p_CTray_SaveWindowPositions)
	{
		match8 = (PBYTE)FindPattern(
			p_CTray_SaveWindowPositions,
			256,
			"\x48\x8B\x83\x00\x00\x00\x00\x48\x83\x78\x08\x00",
			"xxx????xxxxx",
			&numMatches8
		);
		if (match8)
		{
			p_c_trayStatic_m_savedWindowPos = (decltype(p_c_trayStatic_m_savedWindowPos))((PBYTE)p_c_trayStatic + *(int*)(match8 + 3));
		}
	}
	PUBLISH_MATCH_INFO(8);

	// (a) v_hwndDesktop
	// 48 8B 0D ?? ?? ?? ?? 45 33 C9 BA 58 04 00 00
    // .        ^^^^(a)^^^^
	// Ref: GiveDesktopFocus()
	INIT_MATCH_INFO_VARS(9);
	match9 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\x8B\x0D\x00\x00\x00\x00\x45\x33\xC9\xBA\x58\x04\x00\x00",
		"xxx????xxxxxxxx",
		&numMatches9
	);
	if (match9)
	{
		PBYTE match9a = match9 + 0;
		match9a += 7 + *(int*)(match9a + 3);
		p_v_hwndDesktop = (decltype(p_v_hwndDesktop))match9a;
	}
	PUBLISH_MATCH_INFO(9);

	// (a) g_fInSizeMove
	// 48 C1 E0 04 48 03 C1 C7 05 ?? ?? ?? ?? 01 00 00 00
	//                      .     ^^^^(a)^^^^
	// Ref: TrayUI::SetStuckPlace()
	INIT_MATCH_INFO_VARS(10);
	match10 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\xC1\xE0\x04\x48\x03\xC1\xC7\x05\x00\x00\x00\x00\x01\x00\x00\x00",
		"xxxxxxxxx????xxxx",
		&numMatches10
	);
	if (match10)
	{
		PBYTE match10a = match10 + 7;
		match10a += 10 + *(int*)(match10a + 2);
		p_g_fInSizeMove = (decltype(p_g_fInSizeMove))match10a;
	}
	PUBLISH_MATCH_INFO(10);

	// (a) g_fDesktopRaised
	// (b) CTray::_RaiseDesktop()
	// Pattern 1: 3 - (g_fDesktopRaised != 0)
	// 75 15 8B 05 ?? ?? ?? ?? 48 8B CB F7 D8 1B D2 83 C2 03 E8 ?? ?? ?? ??
	//       .     ^^^^(a)^^^^                               .  ^^^^(b)^^^^
	// Ref: CTray::_HandleToggleDesktop()
	INIT_MATCH_INFO_VARS(11);
	usingPattern11 = 1;
	match11 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x75\x15\x8B\x05\x00\x00\x00\x00\x48\x8B\xCB\xF7\xD8\x1B\xD2\x83\xC2\x03\xE8",
		"xxxx????xxxxxxxxxxx",
		&numMatches11
	);
	if (match11)
	{
		PBYTE match11a = match11 + 2;
		match11a += 6 + *(int*)(match11a + 2);
		g_fDesktopRaised = (decltype(g_fDesktopRaised))match11a;

		PBYTE match11b = match11 + 18;
		match11b += 5 + *(int*)(match11b + 1);
		p_CTray__RaiseDesktop = (decltype(p_CTray__RaiseDesktop))match11b;
	}
	else
	{
		// Pattern 2: !g_fDesktopRaised | 2
		// 75 16 39 1D ?? ?? ?? ?? 48 8B CF 0F 94 C3 83 CB 02 8B D3 E8 ?? ?? ?? ??
		//       .     ^^^^(a)^^^^                                  .  ^^^^(b)^^^^
		// Ref: CTray::_HandleToggleDesktop()
		usingPattern11 = 2;
		match11 = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x75\x16\x39\x1D\x00\x00\x00\x00\x48\x8B\xCF\x0F\x94\xC3\x83\xCB\x02\x8B\xD3\xE8",
			"xxxx????xxxxxxxxxxxx",
			&numMatches11
		);
		if (match11)
		{
			PBYTE match11a = match11 + 2;
			match11a += 6 + *(int*)(match11a + 2);
			g_fDesktopRaised = (decltype(g_fDesktopRaised))match11a;

			PBYTE match11b = match11 + 19;
			match11b += 5 + *(int*)(match11b + 1);
			p_CTray__RaiseDesktop = (decltype(p_CTray__RaiseDesktop))match11b;
		}
	}
	PUBLISH_MATCH_INFO(11);

	// (a) c_trayStatic.m_hwndLastActive
	// Pattern 1: Long jump
	// 48 8B 35 ?? ?? ?? ?? 48 85 F6 0F 84 ?? ?? ?? ?? 48 8B CE
	// .        ^^^^(a)^^^^
	// Ref: CTray::_RunDlgThreadProc()
	INIT_MATCH_INFO_VARS(12);
	usingPattern12 = 1;
	match12 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\x8B\x35\x00\x00\x00\x00\x48\x85\xF6\x0F\x84\x00\x00\x00\x00\x48\x8B\xCE",
		"xxx????xxxxx????xxx",
		&numMatches12
	);
	if (match12)
	{
		PBYTE match12a = match12;
		match12a += 7 + *(int*)(match12a + 3);
		p_c_trayStatic_m_hwndLastActive = (decltype(p_c_trayStatic_m_hwndLastActive))match12a;
	}
	else
	{
		// Pattern 2: Short jump
		// 48 8B 35 ?? ?? ?? ?? 48 85 F6 74 ?? 48 8B CE
		// .        ^^^^(a)^^^^
		// Ref: CTray::_RunDlgThreadProc()
		usingPattern12 = 2;
		match12 = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8B\x35\x00\x00\x00\x00\x48\x85\xF6\x74\x00\x48\x8B\xCE",
			"xxx????xxxx?xxx",
			&numMatches12
		);
		if (match12)
		{
			PBYTE match12a = match12;
			match12a += 7 + *(int*)(match12a + 3);
			p_c_trayStatic_m_hwndLastActive = (decltype(p_c_trayStatic_m_hwndLastActive))match12a;
		}
	}
	PUBLISH_MATCH_INFO(12);

	// GetDestinationItemFromDataObjectHelper()
	// 48 89 5C 24 ?? 48 89 54 24 ?? 55 56 57 48 8B EC 48 83 EC 50 49 83 20 00
	// Ref: Itself
	INIT_MATCH_INFO_VARS(13);
	match13 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\x89\x5C\x24\x00\x48\x89\x54\x24\x00\x55\x56\x57\x48\x8B\xEC\x48\x83\xEC\x50\x49\x83\x20\x00",
		"xxxx?xxxx?xxxxxxxxxxxxxx",
		&numMatches13
	);
	if (match13)
	{
		p_GetDestinationItemFromDataObjectHelper = (decltype(p_GetDestinationItemFromDataObjectHelper))match13;
	}
	PUBLISH_MATCH_INFO(13);

	// (a) g_pForegroundControl
	// 40 53 48 83 EC 20 48 8B 0D ?? ?? ?? ?? 48 8B DA 48 85 C9 0F 85
	//                   .        ^^^^(a)^^^^
	// Ref: CInitializeTrayForegroundControl::InitializeTrustedComponentForegroundControl()
	INIT_MATCH_INFO_VARS(14);
	match14 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\xDA\x48\x85\xC9\x0F\x85",
		"xxxxxxxxx????xxxxxxxx",
		&numMatches14
	);
	if (match14)
	{
		PBYTE match14a = match14 + 6;
		match14a += 7 + *(int*)(match14a + 3);
		p_g_pForegroundControl = (decltype(p_g_pForegroundControl))match14a;
	}
	PUBLISH_MATCH_INFO(14);

	// (a) EnsureTabletButtonThreadRunningIfNeeded()
	// 48 83 EC 28 B9 56 00 00 00
	// Ref: Itself
	INIT_MATCH_INFO_VARS(15);
	match15 = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x48\x83\xEC\x28\xB9\x56\x00\x00\x00",
		"xxxxxxxxx",
		&numMatches15
	);
	if (match15)
	{
		p_EnsureTabletButtonThreadRunningIfNeeded = (decltype(p_EnsureTabletButtonThreadRunningIfNeeded))match15;
	}
	PUBLISH_MATCH_INFO(15);

	// TrayUI_CreateInstance()
	// 4C 8D 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0
	// Ref: CTray::Init()
	INIT_MATCH_INFO_VARS(TUCI);
	matchTUCI = (PBYTE)FindPattern(
		pFile, dwSize,
		"\x4C\x8D\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x85\xC0",
		"xxx????xxx????x????xx",
		&numMatchesTUCI
	);
	PUBLISH_MATCH_INFO(TUCI);

	// TaskbarHasFocus
	//

	if (matches->size() != ARRAYSIZE(ElementDefs))
	{
		__fastfail(FAST_FAIL_INVALID_ARG);
	}
}

bool CPatternCheckerSuiteModule_Explorer::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	if (!CPatternCheckerSuiteModule_Base::ShouldIncludeFile(fileInfo))
		return false;

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	// return true; // Temporary
	return build >= 15063 && build <= 19041;
}

void CPatternCheckerSuiteModule_Explorer::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	// anything before 15063, after 20348, and anything non-x64, mark as don't care (numMatches = -1)
	if (build < 15063 || build > 20348 || fileInfo.machineType != IMAGE_FILE_MACHINE_AMD64)
	{
		for (PatternMatchInfo& match : *matches)
		{
			match.numMatches = -1;
		}
	}
}
