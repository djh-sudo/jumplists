#pragma once
#pragma once
/*
* Create by djh-sudo 2022-08-03
* JumpList file Analysis
* JumpList file often in following path
* C:/Users/%username%/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/
*/

#include <locale>
#include <codecvt>
#include <iostream>
#include <sstream>
#include <list>
#include <unordered_map>
#include <string>
#include <regex>
#include <Windows.h>
#include <assert.h>
#include "LNK.h"


typedef __int64 QWORD;

#define ID_MSAT          0xfffffffc
#define ID_SAT           0xfffffffd
#define ID_SECTOR_END    0xfffffffe
#define ID_UNUSED        0xffffffff

#define LITTLE_ENDIAN    0xfeff

#define ID_DIR_EMPTY     0x00
#define ID_DIR_STORAGE   0x01
#define ID_DIR_STREAM    0x02
#define ID_DIR_LOCK      0x03
#define ID_DIR_PROPERTY  0x04
#define ID_DIR_ROOT      0x05

#define SAT_SECTOR_COUNT  109
#define SECTOR_SIZE       512
#define SID_COUNT         128
#define DIR_SIZE          128
#define SHORT_SECTOR_SIZE 64

#define WIN_10_ENTRY     130
#define WIN_7_ENTRY      114
#define LOOP_SIZE        4

typedef struct _OLE_HEADER {
	/* Offset  Description*/
	/* 00 */   BYTE magicNumber[8];
	/* 08 */   BYTE guid[16];
	/* 24 */   WORD minorVersion;
	/* 26 */   WORD majorVersion;
	/* 28 */   WORD byteOrder;
	/* 30 */   WORD dwSector;
	/* 32 */   WORD dwShortSector;
	/* 34 */   BYTE reserved0[10];
	/* 44 */   DWORD countSAT;
	/* 48 */   DWORD firstDirPos;
	/* 52 */   DWORD reserved1;
	/* 56 */   DWORD dwStandardStream;
	/* 60 */   DWORD firstSSATPos;
	/* 64 */   DWORD countSSAT;
	/* 68 */   DWORD firsMSATPos;
	/* 72 */   DWORD countMSAT;
	/* 76 */   DWORD SIDs[SAT_SECTOR_COUNT];
}OLE_HEADER;

typedef struct _OLE_DIRECTORY_ENTRY {
	/* offset  Description */
	/*  0  */   wchar_t dirName[32];
	/*  64 */   WORD dwDirName;
	/*  66 */   BYTE type;
	/*  67 */   BYTE nodeColor;
	/*  68 */   DWORD leftChild;
	/*  72 */   DWORD rightChild;
	/*  76 */   DWORD subRoot;
	/*  80 */   BYTE classId[16];
	/*  96 */   DWORD userFlags;
	/* 100 */   FILETIME createTime;
	/* 108 */   FILETIME modifyTime;
	/* 116 */   DWORD firstPos;
	/* 120 */   DWORD dwStream;
	/* 124 */   DWORD reserved;

}OLE_DIR;

typedef struct _DEST_LIST_HEAD {
	/* offset Description */
	/* 0  */   DWORD version;
	/* 4  */   DWORD szEntry;
	/* 8  */   DWORD fixNumber;
	/* 12 */   DWORD counter;
	/* 16 */   QWORD szPreEntry;
	/* 24 */   QWORD szOperator;
}DL_HEAD;


/*
* This format is used on Windows 10 platform
* Warning! Windows 7 maybe different from this format!
* Also See
* https://www.forensicfocus.com/forums/general/windows-10-and-jump-lists/#post-6576701
*/

typedef struct _DEST_LIST_ENTRY_10 {
	/* offset Description */
	/*  0  */  BYTE checksum[8];
	/*  8  */  BYTE newVolID[16];
	/* 24  */  BYTE ObjID[16];
	/* 40  */  BYTE BirthVolID[16];
	/* 56  */  BYTE BirthObjID[16];
	/* 72  */  BYTE padding0[16];
	/* 88  */  DWORD entryID;
	/* 92  */  BYTE padding1[8];
	/* 100 */  FILETIME lastAccessTime;
	/* 108 */  DWORD entryPIN;
	/* 112 */  DWORD fixed0;
	/* 116 */  DWORD fixed1;
	/* 120 */  BYTE fixed2[8];
	/* 128 */  WORD szPath;
	/* 130 */  // wchar_t* path;
}DL_ENTRY10;

/*
* This format is used on windows 7/8 platform
* Warning! Windows 10 maybe different from this format!
*/

typedef struct _DEST_LIST_ENTRY_7 {
	/* offset Description */
	/*  0  */  BYTE checksum[8];
	/*  8  */  BYTE newVolID[16];
	/* 24  */  BYTE ObjID[16];
	/* 40  */  BYTE BirthVolID[16];
	/* 56  */  BYTE BirthObjID[16];
	/* 72  */  BYTE padding0[16];
	/* 88  */  QWORD entryID;
	/* 96  */  DWORD pointCounter;
	/* 100 */  FILETIME lastAccessTime;
	/* 108 */  DWORD entryPIN;
	/* 112 */  WORD szPath;
	/* 114 */  wchar_t* Path;
}DL_ENTRY7;

/*
* MemoryLink Used to load sector
* Each sector size is 512 bytes
*/
typedef struct _MEMORY_BUFFER_LINK {
	BYTE* buffer;
	_MEMORY_BUFFER_LINK* next;
}MBL;


class DL_ENTRY {

public:

	void Init() {
		m_path = L"";
		m_lastRecordTime = "";
		m_createTime = "";
		m_modifyTime = "";
		m_entryID = -1;
	}

	void SetLastAccessTime(SYSTEMTIME sysTime) {
		char tmpTime[32] = { 0 };
		sprintf(tmpTime, "%04d/%02d/%02d %02d:%02d:%02d",
			sysTime.wYear, sysTime.wMonth, sysTime.wDay,
			sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
		this->m_lastRecordTime = std::string(tmpTime, 32);
		return;
	}

	void SetCreateTime(SYSTEMTIME sysTime) {
		char tmpTime[32] = { 0 };
		sprintf(tmpTime, "%04d/%02d/%02d %02d:%02d:%02d",
			sysTime.wYear, sysTime.wMonth, sysTime.wDay,
			sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
		this->m_createTime = std::string(tmpTime, 32);
		return;
	}

	void SetModifyTime(SYSTEMTIME sysTime) {
		char tmpTime[32] = { 0 };
		sprintf(tmpTime, "%04d/%02d/%02d %02d:%02d:%02d",
			sysTime.wYear, sysTime.wMonth, sysTime.wDay,
			sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
		this->m_modifyTime = std::string(tmpTime, 32);
		return;
	}

	bool SetPath(const wchar_t* p, DWORD dwPath) {
		m_path = std::wstring(p, dwPath);
		if (m_path.size() != dwPath) {
			return false;
		}
		return true;
	}

	bool SetPath(std::wstring path) {
		m_path = path;
		return true;
	}

	void SetEntryID(DWORD id) {
		m_entryID = id;
	}

	std::wstring GetPath() const {
		return m_path;
	}

	std::string GetLastRecordTime() const {
		return m_lastRecordTime;
	}

	std::string GetCreateTime() const {
		return m_createTime;
	}

	std::string GetModifyTime() const {
		return m_modifyTime;
	}

	DL_ENTRY() {
		m_entryID = -1;
	};

	~DL_ENTRY() = default;

private:
	std::wstring m_path;
	std::string m_lastRecordTime;
	std::string m_createTime;
	std::string m_modifyTime;
	DWORD m_entryID;

};

/*
* Object Linking and Embedding(OLE) Compound File(CF)
* OLE-CF file format
* Also See
* https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc
*/
class OLE_OBJECT {

public:

	bool Init(std::string path) {
		SATChain.clear();
		SSATChain.clear();

		memset(&m_oleHeader, 0, sizeof(m_oleHeader));

		m_fp = fopen(path.c_str(), "rb");
		if (m_fp == NULL) return false;
		else {
			fread(&m_oleHeader, sizeof(m_oleHeader), 1, m_fp);
			if ((1 << m_oleHeader.dwSector) == SECTOR_SIZE && (1 << m_oleHeader.dwShortSector) == SHORT_SECTOR_SIZE)
				return true;
			else
				return false;
		}
	}

	bool GetDirs() {
		if (!CheckValid()) return false;
		if (SATChain.find(m_oleHeader.firstDirPos) == SATChain.end()) return false;

		DWORD countSector = SATChain[m_oleHeader.firstDirPos].size();
		// one sector(512) can store 4 directory entries (128)
		m_dwDirs = countSector << 2;
		m_dirEntrys = new OLE_DIR[m_dwDirs];
		if (m_dirEntrys == NULL) return false;
		memset(m_dirEntrys, 0, m_dwDirs * sizeof(OLE_DIR));

		DWORD offset = 0;
		std::list<DWORD>::iterator it = SATChain[m_oleHeader.firstDirPos].begin();
		std::list<DWORD>::iterator end = SATChain[m_oleHeader.firstDirPos].end();

		for (DWORD i = 0; i < countSector && it != end; ++i, it++) {
			offset = GetBlock(*it);
			assert(fseek(m_fp, offset, SEEK_SET) == 0);
			for (int k = 0; k < 4; ++k) {
				fread(m_dirEntrys + i * 4 + k, DIR_SIZE, 1, m_fp);
				if (!lstrcmpW((m_dirEntrys + i * 4 + k)->dirName, L"DestList")) {
					m_destList = i * 4 + k;
					m_dwDestList = (m_dirEntrys + i * 4 + k)->dwStream;
				}
				char name[MAX_PATH] = { 0 };
				WideCharToMultiByte(CP_ACP, 0, (m_dirEntrys + i * 4 + k)->dirName, -1, name, MAX_PATH, NULL, NULL);
				m_entryMap[name] = i * 4 + k;
			}
		}
		return true;
	}

	bool AquireSATChain() {
		if (!CheckValid()) return false;
		DWORD sector[SID_COUNT] = { 0 };
		std::unordered_map<int, int>isOverflow;
		DWORD check = 0;

		for (DWORD i = 0; i < m_oleHeader.countSAT; ++i) {
			DWORD offset = GetBlock(m_oleHeader.SIDs[i]);
			assert(fseek(m_fp, offset, SEEK_SET) == 0);
			fread(sector, SECTOR_SIZE, 1, m_fp);

			DWORD prefix = i << 7;
			DWORD threshHold = (i + 1) << 7;
			DWORD updateFlag = -1;

			for (int j = 0; j < SID_COUNT; ++j) {
				updateFlag = -1;

				if (sector[j] == ID_UNUSED) continue;
				if (sector[j] == ID_SAT) {
					++check;
					continue;
				}
				else {
					DWORD index = j + prefix;
					DWORD nextNode = 0;

					std::list<DWORD>tmp;
					if (isOverflow.find(index) != isOverflow.end()) {
						tmp = SATChain[isOverflow[index]];
						updateFlag = isOverflow[index];
					}
					else {
						tmp.clear();
					}
					do {
						if (index >= prefix) {
							tmp.push_back(index);
							nextNode = sector[index - prefix];
							sector[index - prefix] = ID_UNUSED;
							index = nextNode;
						}
						else {
							assert(SATChain.find(index) != SATChain.end());
							tmp.splice(tmp.end(), SATChain[index]);
							SATChain.erase(index);
							break;
						}

					} while (index < threshHold && index != ID_SECTOR_END);
					// update FAT Chain
					if (updateFlag == -1)  SATChain[j + prefix] = tmp;
					else  SATChain[updateFlag] = tmp;
					// Handle index overflow 
					if (index >= threshHold && index != ID_SECTOR_END) {
						if (updateFlag == -1)  isOverflow[index] = j + prefix;
						else  isOverflow[index] = updateFlag;
					}
					if (index < prefix && index != ID_SECTOR_END) {
						for (auto& it : isOverflow) {
							if (it.second == index) it.second = updateFlag;
						}
					}
				}
			}
		}
		isOverflow.clear();
		assert(m_oleHeader.countSAT == check);
		return true;
	}

	bool AquireSSATChain() {
		if (!CheckValid()) return false;
		if (SATChain.find(m_oleHeader.firstSSATPos) == SATChain.end()) {
			return false;
		}

		std::list<DWORD>::iterator it = SATChain[m_oleHeader.firstSSATPos].begin();
		std::list<DWORD>::iterator end = SATChain[m_oleHeader.firstSSATPos].end();

		DWORD sector[SID_COUNT] = { 0 };
		std::unordered_map<int, int>isOverflow;
		DWORD i = 0;
		
		for (it; it != end && i < m_oleHeader.countSSAT; it++, ++i) {
			DWORD offset = GetBlock(*it);
			assert(fseek(m_fp, offset, SEEK_SET) == 0);
			fread(sector, SECTOR_SIZE, 1, m_fp);

			DWORD prefix = i << 7;
			DWORD threshHold = (i + 1) << 7;
			DWORD updateFlag = -1;

			for (DWORD k = 0; k < SID_COUNT; ++k) {
				updateFlag = -1;
				if (sector[k] == ID_UNUSED) continue;
				if (sector[k] == ID_SAT) {
					continue;
				}
				else {
					std::list<DWORD>tmp;
					DWORD index = k + prefix;
					DWORD nextNode = 0;
					
					if (isOverflow.find(index) != isOverflow.end()) {
						tmp = SSATChain[isOverflow[index]];
						updateFlag = isOverflow[index];
					}
					else {
						tmp.clear();
					}

					do {
						if (index >= prefix) {
							tmp.push_back(index);
							nextNode = sector[index - prefix];
							sector[index - prefix] = ID_UNUSED;
							index = nextNode;
						}
						else {
							assert(SSATChain.find(index) != SSATChain.end());
							// merge
							tmp.splice(tmp.end(), SSATChain[index]);
							SSATChain.erase(index);
							break;
						}
					} while (index < threshHold && index != ID_SECTOR_END);
					// update SSAT Chain
					if (updateFlag == -1)  SSATChain[k + prefix] = tmp;
					else  SSATChain[updateFlag] = tmp;
					// Handle index overflow 
					if (index >= threshHold && index != ID_SECTOR_END) {
						if (updateFlag == -1)  isOverflow[index] = k + prefix;
						else  isOverflow[index] = updateFlag;
					}
					if (index < prefix && index != ID_SECTOR_END) {
						for (auto& it : isOverflow) {
							if (it.second == index) it.second = updateFlag;
						}
					}
				}
			}
		}
		isOverflow.clear();
		return true;
	}

	std::vector<DL_ENTRY> & GetdlEntrys() {
		return m_dlEntrys;
	}

	bool GetDestListFromSAT() {
		if (m_destList == -1)  return false;
		if (m_destList >= m_dwDirs) return false;
		if (!InitBufferMemory()) return false;

		DWORD index = (m_dirEntrys + m_destList)->firstPos;

		if (SATChain.find(index) == SATChain.end()) return false;

		std::list<DWORD>::iterator it = SATChain[index].begin();
		std::list<DWORD>::iterator end = SATChain[index].end();

		DWORD offset = 0;
		DWORD loopId = 0;
		DWORD dwRead = 32;
		DWORD dwEntrys = 0;
		DWORD curPos = 0;
		DWORD dwOldRead = 0;
		bool endFlag = false;

		for (int i = 0; i < 4 && it != end; ++i) {
			offset = GetBlock(*it++);
			assert(fseek(m_fp, offset, SEEK_SET) == 0);
			fread(m_LoopBuffer[i].buffer, SECTOR_SIZE, 1, m_fp);
		}

		memcpy(&m_dlHeader, m_LoopBuffer[loopId].buffer, sizeof(m_dlHeader));
		dwEntrys = m_dlHeader.szEntry;

		BYTE content[SECTOR_SIZE << 1] = { 0 };
		DWORD i = 0;
		for (i = 0; i < dwEntrys;) {
			memset(content, 0, SECTOR_SIZE << 1);
			UpdateMemory(content, loopId, dwRead);
			// Analysis DestList
			dwOldRead = AnalyseDestList(content, i);
			if (dwOldRead == 0) {
				// slow path
				if (i < dwEntrys) {
					BYTE largeMemory[SECTOR_SIZE << 2] = { 0 };
					memcpy(largeMemory, content, SECTOR_SIZE << 1);
					UpdateMemory(largeMemory + (SECTOR_SIZE << 1), loopId, 0);
					dwOldRead = AnalyseDestList(largeMemory, i, SECTOR_SIZE << 1);
				}
				if (dwOldRead == 0) {
					break;
				}
			}
			dwRead += dwOldRead;
			while (dwRead > SECTOR_SIZE) {
				if (it != end) {
					UpdateSector(*it++, loopId, dwRead, endFlag);
					continue;
				}
				if (it == end) {
					UpdateSector(0, loopId, dwRead, true);
				}
			}
		}
		if (i < dwEntrys) {
			
			return false;
		}
		return true;
	}

	DWORD GetSSAT(PBYTE buffer, DWORD start) {
		if (start == -1)  return 0;
		if (start >= m_dwDirs) return 0;
		if ((m_dirEntrys + start)->dwStream > 4096) return 0;
		DWORD index = (m_dirEntrys + start)->firstPos;
		if (SSATChain.find(index) == SSATChain.end()) return false;
		if (SSATChain[index].size() > 64) return false;
		
		DWORD firstIdx = m_dirEntrys->firstPos;
		std::list<DWORD>::iterator it = SATChain[firstIdx].begin();
		std::list<DWORD>::iterator end = SATChain[firstIdx].end();

		std::list<DWORD>::iterator ssatIt = SSATChain[index].begin();
		std::list<DWORD>::iterator ssatEnd = SSATChain[index].end();

		DWORD offset = 0;
		DWORD dwRead = 0;

		for (int k = 0; ssatIt != ssatEnd && it != end; k++) {
			offset = GetBlock(*it++);
			DWORD threshHold = (k + 1) << 9;
			DWORD prefix = k << 9;

			while (ssatIt != ssatEnd && GetMiniBlock(*ssatIt) < threshHold) {
				DWORD index = GetMiniBlock(*ssatIt) - prefix;
				assert(fseek(m_fp, offset + index, SEEK_SET) == 0);
				fread(buffer + dwRead, SHORT_SECTOR_SIZE, 1, m_fp);
				ssatIt++;
				dwRead += SHORT_SECTOR_SIZE;
			}
		}
		// assert(szRead >= (m_dirEntrys + start)->szStream);
		return dwRead;
	}

	bool GetDestListFromSSAT() {
		if (m_dwDestList > 4096) return false;
		DWORD offset = 0;
		DWORD dwRead = 0;
		DWORD dwEntrys = 0;
		DWORD dwOldRead = 0;

		BYTE content[SECTOR_SIZE << 3] = { 0 };
		dwRead = GetSSAT(content, m_destList);
		if (dwRead == 0) {
			return false;
		}
		memcpy(&m_dlHeader, content, sizeof(m_dlHeader));
		dwEntrys = m_dlHeader.szEntry;

		dwRead = 32;
		DWORD i = 0;
		for (i = 0; i < dwEntrys;) {
			// Analysis DestList
			dwOldRead = AnalyseDestList(content + dwRead, i);
			if (dwOldRead == 0 || dwOldRead > (SECTOR_SIZE << 1)) break;
			dwRead += dwOldRead;
			if (dwRead > 4096) break;
		}
		if (i < dwEntrys) {
			return false;
		}
		return true;
	}

	bool GetLNKInfoFromSSAT(DWORD entryId) {
		PBYTE content = new BYTE[SECTOR_SIZE << 3];
		DWORD dwRead = 0;
		bool status = false;
		if (content == NULL) {
			return false;
		}
		do {
			memset(content, 0, SECTOR_SIZE << 3);
			std::ostringstream ss;
			ss << std::hex << entryId;
			std::string res = ss.str();
			dwRead = GetSSAT(content, m_entryMap[res]);
			if (dwRead == 0) {
				break;
			}
			m_lnk.Init();
			status = m_lnk.Parser(content, dwRead);
			if (status == false) {
				break;
			}

		} while (false);

		if(content != NULL){
			delete[] content;
			content = NULL;
		}
		return status;
	}

	DWORD GetdwDestList() const {
		return m_dwDestList;
	}

	OLE_OBJECT() {
		memset(&m_oleHeader, 0, sizeof(m_oleHeader));
		m_dirEntrys = NULL;
		m_dwDirs = 0;
		SATChain.clear();
		SSATChain.clear();
		m_fp = NULL;
		m_destList = -1;
		m_dwDestList = 0;
		m_dlEntrys.clear();
		m_entryMap.clear();
		for (int i = 0; i < LOOP_SIZE; ++i) {
			m_LoopBuffer[i].buffer = NULL;
			m_LoopBuffer[i].next = NULL;
		}
	}

	~OLE_OBJECT() {
		// free memory
		delete[] m_dirEntrys;
		m_dirEntrys = NULL;

		if (m_fp != NULL) {
			fclose(m_fp);
			m_fp = NULL;
		}
		for (auto& it : SATChain) {
			it.second.clear();
		}
		SATChain.clear();
		SSATChain.clear();
		for (int i = 0; i < LOOP_SIZE; ++i) {
			if (m_LoopBuffer[i].buffer != NULL) {
				delete[] m_LoopBuffer[i].buffer;
				m_LoopBuffer[i].buffer = NULL;
				m_LoopBuffer[i].next = NULL;
			}
			else
				continue;
		}

		std::vector<DL_ENTRY>().swap(m_dlEntrys);
		m_dlEntrys.clear();
		m_entryMap.clear();
	}

private:

	inline bool CheckValid() {
		return !(m_fp == NULL || m_oleHeader.SIDs == NULL);
	}

	bool InitBufferMemory() {
		int i = 0;
		bool flag = true;
		for (i; i < LOOP_SIZE; ++i) {
			m_LoopBuffer[i].buffer = new BYTE[SECTOR_SIZE];
			if (m_LoopBuffer[i].buffer == NULL) {
				flag = false;
				break;
			}
			memset(m_LoopBuffer[i].buffer, 0, SECTOR_SIZE);
		}
		for (int k = 0; k < LOOP_SIZE && flag; ++k) {
			m_LoopBuffer[k].next = &m_LoopBuffer[(k + 1) % LOOP_SIZE];
		}

		if (i < LOOP_SIZE) {
			--i;
			while (i >= 0) {
				delete[] m_LoopBuffer[i].buffer;
				m_LoopBuffer[i].buffer = NULL;
				m_LoopBuffer[i].next = NULL;
				--i;
			}
		}
		return flag;
	}

	DWORD AnalyseDestList(const BYTE* content, DWORD& counter, int baseLen = SECTOR_SIZE) {
		if (content == NULL) return 0;
		DWORD dwRead = 0;
		DL_ENTRY10* entry;
		DL_ENTRY obj;
		SYSTEMTIME sysTime;

		do {
			entry = (DL_ENTRY10 *)(content + dwRead);
			if (((entry->szPath << 1) + WIN_10_ENTRY + 4 + dwRead) < (baseLen << 1)) {
				obj.Init();
				ConvertTime(&entry->lastAccessTime, &sysTime);
				obj.SetLastAccessTime(sysTime);
				obj.SetEntryID(entry->entryID);
				obj.SetPath((wchar_t*)((BYTE*)content + WIN_10_ENTRY + dwRead), entry->szPath);
				if (GetLNKInfoFromSSAT(entry->entryID)) {
					if (entry->szPath <= 32 && CheckRules(obj.GetPath())) {
						obj.SetPath(m_lnk.GetLocalPath());
					}
				}
				if (m_lnk.HasTime()) {
					FILETIME createTime = m_lnk.GetCreateTime();
					ConvertTime(&createTime, &sysTime);
					obj.SetCreateTime(sysTime);

					FILETIME modifyTime = m_lnk.GetWriteTime();
					ConvertTime(&modifyTime, &sysTime);
					obj.SetModifyTime(sysTime);
				}
				m_dlEntrys.push_back(obj);
				dwRead += WIN_10_ENTRY + (entry->szPath << 1) + 4;
				++counter;
			}
			else {
				break;
			}
		} while (dwRead < (baseLen) - WIN_10_ENTRY && counter < m_dlHeader.szEntry);
		return dwRead;
	}

	DWORD GetBlock(const DWORD sid) const {
		return (sid + 1) * SECTOR_SIZE;
	}

	DWORD GetMiniBlock(const DWORD sid) const {
		return sid * SHORT_SECTOR_SIZE;
	}

	bool ConvertTime(FILETIME* fileTime, LPSYSTEMTIME sysTime) {
		assert(sysTime != NULL);
		FILETIME localTime[sizeof(FILETIME)] = { 0 };
		FileTimeToLocalFileTime(fileTime, localTime);
		if (localTime == NULL) return false;
		FileTimeToSystemTime(localTime, sysTime);
		if (sysTime == NULL) return false;
		return true;
	}

	void UpdateSector(const DWORD off, DWORD& loopId, DWORD& dwRead, bool flag = false) {
		// Load an new sector
		if (!flag) {
			DWORD offset = GetBlock(off);
			assert(fseek(m_fp, offset, SEEK_SET) == 0);
			memset(m_LoopBuffer[loopId].buffer, 0, SECTOR_SIZE);
			fread(m_LoopBuffer[loopId].buffer, SECTOR_SIZE, 1, m_fp);
		}
		else {
			memset(m_LoopBuffer[loopId].buffer, 0, SECTOR_SIZE);
		}
		// step 2 Step Next Memory
		loopId = (loopId + 1) % LOOP_SIZE;
		// step 3 Update dwRead
		dwRead = dwRead - SECTOR_SIZE;
		return;
	}

	void UpdateMemory(BYTE* content, const DWORD loopId, const DWORD dwRead) {
		DWORD curPos = SECTOR_SIZE - dwRead;
		memcpy(content, m_LoopBuffer[loopId].buffer + dwRead, curPos);
		memcpy(content + curPos, m_LoopBuffer[(loopId + 1) % LOOP_SIZE].buffer, SECTOR_SIZE);
		curPos += SECTOR_SIZE;
		memcpy(content + curPos, m_LoopBuffer[(loopId + 2) % LOOP_SIZE].buffer, dwRead);
		return;
	}

	bool CheckRules(std::wstring str) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::string res = converter.to_bytes(str);
		std::regex reg("^[0-9a-zA-Z]+$");
		bool check = std::regex_match(res, reg);
		return check;
	}

	private:
		FILE* m_fp;
		OLE_HEADER m_oleHeader;/* File header 512 bytes */
		OLE_DIR* m_dirEntrys;  /* each dir entry is 128 bytes*/
		std::unordered_map<std::string, DWORD>m_entryMap;
		DWORD m_dwDirs;
		std::unordered_map<DWORD, std::list<DWORD>>SATChain;
		std::unordered_map<DWORD, std::list<DWORD>>SSATChain;
		/* DestList index in dir entry
		* if DestList not exits,  index = -1
		*/
		DWORD m_destList;
		DWORD m_dwDestList;
		DL_HEAD m_dlHeader;    /* DestList Header 32 bytes */
		std::vector<DL_ENTRY> m_dlEntrys;
		MBL m_LoopBuffer[LOOP_SIZE];
		LNK_FILE m_lnk;
};

