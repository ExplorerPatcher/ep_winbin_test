#pragma once

#include "PatternCheckerSuiteModule_Base.h"

class CPatternCheckerSuiteModule_TwinUIPCShell final : public CPatternCheckerSuiteModule_Base
{
	static const ElementDef ElementDefs[];

public:
	CPatternCheckerSuiteModule_TwinUIPCShell();

	void CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches) override;

	void CheckPatterns_Various(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches);
	void CheckPatterns_SMA(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches);
	void CheckPatterns_JVP(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches);

	bool ShouldIncludeFile(const FileInfo& fileInfo) const override;
	void PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches) override;
};
