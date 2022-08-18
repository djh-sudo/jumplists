#pragma once
#include <string>
#include <Windows.h>


/*
* Link(LNK) file parser
* Also See
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
*/

typedef struct _LINK_HEADER{
	/* Off[DEC] Description */
	/* 00 */   DWORD dwHeader;
	/* 04 */   CLSID linkClsid;
	/* 20 */   DWORD flag;
	/* 24 */   DWORD fileAttributes;
	/* 28 */   FILETIME createTime;
	/* 36 */   FILETIME AccessTime;
	/* 44 */   FILETIME writeTime;
	/* 52 */   DWORD dwFileSize;
	/* 56 */   DWORD iconIndex;
	/* 60 */   DWORD showCommand;
	/* 64 */   WORD hotKey;
	/* 66 */   BYTE padding[10];
	/* 76 bytes totally! */
} LNK_HEADER, * PLNK_HEADER;

/*
* LinkTargetIDList structure
* Also See
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/881d7a83-07a5-4702-93e3-f9fc34c3e1e4
*/


typedef struct _IDLIST {
	WORD listSize;
	std::string szContent;
} ID_LIST, *PID_LIST;


typedef struct _LINK_TARGET_ID_LIST {
	WORD IDListSize;
	CLSID computer;
	PID_LIST lists[1];
	WORD terminalId;
}LNK_TID_LIST, * PLNK_TID_LIST;


/*
* Link info structure
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/6813269d-0cc8-4be2-933f-e96e8e3412dc
*/
typedef struct _LINK_INFO {
	DWORD dwLinkSize;
	DWORD dwLinkHeaderSize;
	DWORD flag;
	DWORD volumIdOffset;
	DWORD localBasePathOffset;
	DWORD padding;
	DWORD suffixOffset;

} LINK_INFO, * PLINK_INFO;

class LNK_FILE {
	
public:
	
	void Init() {
		memset(&m_header, 0, sizeof(m_header));
		memset(&m_list, 0, sizeof(m_list));
		m_wsPath = L"";
		m_hasTime = false;
	}

	bool Parser(const void * buffer, DWORD len) {
		bool flag = false;
		DWORD acc = 0;
		do {
			if (len < 76) {
				break;
			}
			memcpy(&m_header, buffer, sizeof(m_header));
			if (m_header.dwHeader != 76) {
				m_hasTime = false;
				break;
			}
			acc = 76;
			m_hasTime = true;
			bool hasLinkTargetIDList = ((m_header.flag & 0x00000001) == 0x00000001);
			bool HasLinkInfo = ((m_header.flag & 0x00000002) == 0x00000002);
			if (hasLinkTargetIDList == true) {
				PLNK_TID_LIST pList = (PLNK_TID_LIST)((PBYTE)buffer + acc);
				if (len < pList->IDListSize + acc) {
					break;
				}
				acc += pList->IDListSize + 2;
			}
			if (HasLinkInfo == true) {
				PLINK_INFO info = (PLINK_INFO)((PBYTE)buffer + acc);
				if (len < info->suffixOffset + acc) {
					break;
				}
				int dwPath = info->suffixOffset - info->localBasePathOffset;
				if (dwPath <= 0) {
					break;
				}
				acc += info->localBasePathOffset;
				char path[MAX_PATH] = { 0 };
				memcpy(path, (PBYTE)buffer + acc, dwPath);
				wchar_t wPath[MAX_PATH] = { 0 };
				int len = MultiByteToWideChar(CP_ACP, 0, path, -1, wPath, MAX_PATH);
				m_wsPath = std::wstring(wPath, len);

				flag = true;
			}
			else {
				flag = false;
				break;
			}

		} while (false);

		return flag;
	}

	FILETIME GetCreateTime() const {
		BYTE zero[8] = { 0 };
		if (memcmp(&m_header.createTime, &zero, 8) == 0) {
			return m_header.createTime;
		}
		return m_header.createTime;
	}

	FILETIME GetWriteTime() const {
		return m_header.writeTime;
	}

	std::wstring GetLocalPath() const {
		return m_wsPath;
	}

	bool HasTime() const{
		return m_hasTime;
	}

	LNK_FILE() {
		memset(&m_header, 0, sizeof(m_header));
		memset(&m_list, 0, sizeof(m_list));
		m_hasTime = false;
	}
	~LNK_FILE() = default;

private:
	LNK_HEADER m_header;
	LNK_TID_LIST m_list;
	std::wstring m_wsPath;
	bool m_hasTime;
};