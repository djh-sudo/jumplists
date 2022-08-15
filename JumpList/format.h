#pragma once
#pragma once
/*
* Create by djh-sudo 2022-08-03
* JumpList file Analysis
* JumpList file often in following path
* C:/Users/{username}/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/
*/

#include <Windows.h>
#include <assert.h>
#include <list>
#include <unordered_map>
#include <string>

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

typedef struct _OLE_HEADER {
	/* Offset  Description*/
	/* 00 */   BYTE magicNumber[8];
	/* 08 */   BYTE guid[16];
	/* 24 */   WORD minorVersion;
	/* 26 */   WORD majorVersion;
	/* 28 */   WORD byteOrder;
	/* 30 */   WORD szSector;
	/* 32 */   WORD szShortSector;
	/* 34 */   BYTE reserved0[10];
	/* 44 */   DWORD countSAT;
	/* 48 */   DWORD firstDirPos;
	/* 52 */   DWORD reserved1;
	/* 56 */   DWORD szStandardStream;
	/* 60 */   DWORD firstSSATPos;
	/* 64 */   DWORD countSSAT;
	/* 68 */   DWORD firsMSATPos;
	/* 72 */   DWORD countMSAT;
	/* 76 */   DWORD SIDs[SAT_SECTOR_COUNT];
}OLE_HEADER;

typedef struct _OLE_DIRECTORY_ENTRY {
	/* offset  Description */
	/*  0  */   wchar_t dirName[32];
	/*  64 */   WORD szDirName;
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
	/* 120 */   DWORD szStream;
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
	DL_ENTRY() = default;

	~DL_ENTRY() = default;

	void Init() {
		m_path = L"";
		m_lastRecordTime = "";
	}

	void setTime(SYSTEMTIME sysTime) {
		char tmpTime[32] = { 0 };
		sprintf(tmpTime, "%04d/%02d/%02d %02d:%02d:%02d",
			sysTime.wYear, sysTime.wMonth, sysTime.wDay,
			sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
		this->m_lastRecordTime = std::string(tmpTime, 32);
		return;
	}

	bool setPath(const wchar_t* p, DWORD szPath) {
		m_path = std::wstring(p, szPath);
		if (m_path.size() != szPath) {
			// assert(m_path.size() == szPath);
			return false;
		}
		return true;
	}

	std::wstring GetPath() {
		return m_path;
	}

	std::string GetLastRecordTime() {
		return m_lastRecordTime;
	}

private:
	std::wstring m_path;
	std::string m_lastRecordTime;

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
		memset(&oleHeader, 0, sizeof(oleHeader));

		fp = fopen(path.c_str(), "rb");
		if (fp == NULL) return false;
		else {
			fread(&oleHeader, sizeof(oleHeader), 1, fp);
			if ((1 << oleHeader.szSector) == SECTOR_SIZE && (1 << oleHeader.szShortSector) == SHORT_SECTOR_SIZE)
				return true;
			else
				return false;
		}
	}

	bool GetDirs() {
		if (!CheckValid()) return false;
		if (SATChain.find(oleHeader.firstDirPos) == SATChain.end()) return false;

		DWORD countSector = SATChain[oleHeader.firstDirPos].size();
		// one sector(512) can store 4 direntrys(128)
		szDirs = countSector << 2;
		dirEntrys = new OLE_DIR[szDirs];
		if (dirEntrys == NULL) return false;// assert(dirEntrys != NULL);
		memset(dirEntrys, 0, szDirs * sizeof(OLE_DIR));

		DWORD offset = 0;
		std::list<DWORD>::iterator it = SATChain[oleHeader.firstDirPos].begin();
		std::list<DWORD>::iterator end = SATChain[oleHeader.firstDirPos].end();

		for (DWORD i = 0; i < countSector && it != end; ++i, it++) {
			offset = GetBlock(*it);
			assert(fseek(fp, offset, SEEK_SET) == 0);
			for (int k = 0; k < 4; ++k) {
				fread(dirEntrys + i * 4 + k, DIR_SIZE, 1, fp);
				if (!lstrcmpW((dirEntrys + i * 4 + k)->dirName, L"DestList")) {
					destList = i * 4 + k;
					dwDestList = (dirEntrys + i * 4 + k)->szStream;
				}
			}
		}
		return true;
	}

	bool AquireSATChain() {
		if (!CheckValid()) return false;
		DWORD sector[SID_COUNT] = { 0 };
		std::unordered_map<int, int>isOverflow;
		isOverflow.clear();
		DWORD check = 0;

		for (DWORD i = 0; i < oleHeader.countSAT; ++i) {
			DWORD offset = GetBlock(oleHeader.SIDs[i]);
			assert(fseek(fp, offset, SEEK_SET) == 0);
			fread(sector, SECTOR_SIZE, 1, fp);

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
		assert(oleHeader.countSAT == check);
		return true;
	}

	bool AquireSSATChain() {
		if (!CheckValid()) return false;
		return true; // ???
	}

	std::vector<DL_ENTRY> & GetdlEntrys() {
		return dlEntrys;
	}

	bool GetDestList() {
		if (destList == -1)  return false;
		if (destList >= szDirs) return false;
		if (!InitBufferMemory()) return false;

		DWORD index = (dirEntrys + destList)->firstPos;

		if (SATChain.find(index) == SATChain.end()) return false;

		std::list<DWORD>::iterator it = SATChain[index].begin();
		std::list<DWORD>::iterator end = SATChain[index].end();

		DWORD offset = 0;
		DWORD loopId = 0;
		DWORD szRead = 32;
		DWORD szEntrys = 0;
		DWORD curPos = 0;
		DWORD oldszRead = 0;
		bool endFlag = false;

		for (int i = 0; i < 4 && it != end; ++i) {
			offset = GetBlock(*it++);
			assert(fseek(fp, offset, SEEK_SET) == 0);
			fread(LoopBuffer[i].buffer, SECTOR_SIZE, 1, fp);
		}

		memcpy(&dlHeader, LoopBuffer[loopId].buffer, sizeof(dlHeader));
		szEntrys = dlHeader.szEntry;

		BYTE content[SECTOR_SIZE << 1] = { 0 };

		for (DWORD i = 0; i < szEntrys;) {
			memset(content, 0, SECTOR_SIZE << 1);
			UpdateMemory(content, loopId, szRead);
			// Analyse DestList
			oldszRead = AnalyseDestList(content, i);
			if (oldszRead == 0 || oldszRead > (SECTOR_SIZE << 1)) break;
			szRead += oldszRead;
			while (szRead > SECTOR_SIZE) {
				if (it != end) {
					UpdateSector(*it++, loopId, szRead, endFlag);
					continue;
				}
				if (it == end) {
					UpdateSector(0, loopId, szRead, true);
				}
			}
		}
		return true;
	}

	OLE_OBJECT() {
		memset(&oleHeader, 0, sizeof(oleHeader));
		dirEntrys = NULL;
		szDirs = 0;
		SATChain.clear();
		fp = NULL;
		destList = -1;
		dwDestList = 0;
		dlEntrys.clear();
		for (int i = 0; i < 4; ++i) {
			LoopBuffer[i].buffer = NULL;
			LoopBuffer[i].next = NULL;
		}
	}

	~OLE_OBJECT() {
		// free memory
		delete[] dirEntrys;
		dirEntrys = NULL;

		if (fp != NULL) {
			fclose(fp);
			fp = NULL;
		}
		for (auto& it : SATChain) {
			it.second.clear();
		}
		SATChain.clear();

		for (int i = 0; i < 4; ++i) {
			if (LoopBuffer[i].buffer != NULL) {
				delete[] LoopBuffer[i].buffer;
				LoopBuffer[i].buffer = NULL;
				LoopBuffer[i].next = NULL;
			}
			else
				continue;
		}

		std::vector<DL_ENTRY>().swap(dlEntrys);
		dlEntrys.clear();
	}

private:

	inline bool CheckValid() {
		return !(fp == NULL || oleHeader.SIDs == NULL);
	}

	bool InitBufferMemory() {
		int i = 0;
		for (i; i < 4; ++i) {
			LoopBuffer[i].buffer = new BYTE[SECTOR_SIZE];
			if (LoopBuffer[i].buffer == NULL) break;
			memset(LoopBuffer[i].buffer, 0, SECTOR_SIZE);
		}
		for (int k = 0; k < 4; ++k) {
			LoopBuffer[k].next = &LoopBuffer[(k + 1) % 4];
		}

		if (i < 4) {
			--i;
			while (i >= 0) {
				delete[] LoopBuffer[i].buffer;
				LoopBuffer[i].buffer = NULL;
				LoopBuffer[i].next = NULL;
				--i;
			}
			return false;
		}
		return true;
	}

	DWORD AnalyseDestList(const BYTE* content, DWORD& counter) {
		if (content == NULL) return 0;
		DWORD szRead = 0;
		DL_ENTRY10* entry;
		DL_ENTRY obj;
		SYSTEMTIME sysTime;

		// FILETIME lastAccess; // offset :100 - 108
		// WORD szPath = 0;     // offset :128 - 130
		do {
			entry = (DL_ENTRY10*)(content + szRead);
			if (((entry->szPath << 1) + WIN_10_ENTRY + 4 + szRead) < (SECTOR_SIZE << 1)) {
				obj.Init();
				ConvertTime(&entry->lastAccessTime, &sysTime);
				obj.setTime(sysTime);
				obj.setPath((wchar_t*)((BYTE*)content + WIN_10_ENTRY + szRead), entry->szPath);
				dlEntrys.push_back(obj);
				szRead += WIN_10_ENTRY + (entry->szPath << 1) + 4;
				++counter;
			}
			else {
				break;
			}
		} while (szRead < (SECTOR_SIZE << 1) - WIN_10_ENTRY && counter < dlHeader.szEntry);
		return szRead;
	}

	DWORD GetBlock(const DWORD sid) {
		return (sid + 1) * SECTOR_SIZE;
	}

	DWORD GetMiniBlock(const DWORD sid) {
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

	void UpdateSector(const DWORD off, DWORD& loopId, DWORD& szRead, bool flag = false) {
		// Load an new sector
		if (!flag) {
			DWORD offset = GetBlock(off);
			assert(fseek(fp, offset, SEEK_SET) == 0);
			memset(LoopBuffer[loopId].buffer, 0, SECTOR_SIZE);
			fread(LoopBuffer[loopId].buffer, SECTOR_SIZE, 1, fp);
		}
		else {
			memset(LoopBuffer[loopId].buffer, 0, SECTOR_SIZE);
		}
		// step 2 Step Next Memory
		loopId = (loopId + 1) % 4;
		// step 3 Update szRead
		szRead = szRead - SECTOR_SIZE;
		return;
	}

	void UpdateMemory(BYTE* content, const DWORD loopId, const DWORD szRead) {
		DWORD curPos = SECTOR_SIZE - szRead;
		memcpy(content, LoopBuffer[loopId].buffer + szRead, curPos);
		memcpy(content + curPos, LoopBuffer[(loopId + 1) % 4].buffer, SECTOR_SIZE);
		curPos += SECTOR_SIZE;
		memcpy(content + curPos, LoopBuffer[(loopId + 2) % 4].buffer, szRead);
		return;
	}

	private:
		FILE* fp;
		OLE_HEADER oleHeader;/* File header 512 bytes */
		OLE_DIR* dirEntrys;  /* each dir entry is 128 bytes*/
		DWORD szDirs;
		std::unordered_map<DWORD, std::list<DWORD>>SATChain;
		std::unordered_map<DWORD, std::list<DWORD>>SSATChain;
		/* DestList index in dir entry
		* if DestList not exits,  index = -1
		*/
		DWORD destList;
		DWORD dwDestList;
		DL_HEAD dlHeader;    /* DestList Header 32 bytes */
		std::vector<DL_ENTRY> dlEntrys;
		MBL LoopBuffer[4];

};
