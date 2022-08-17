#pragma once
#include <string>
#include <Windows.h>

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
				break;
			}
			acc = 76;
			PLNK_TID_LIST pList = (PLNK_TID_LIST)((PBYTE)buffer + acc);
			if (len < pList->IDListSize + acc) {
				break;
			}
			acc += pList->IDListSize + 2;
			PLINK_INFO info = (PLINK_INFO)((PBYTE)buffer + acc);
			if (len < info->suffixOffset + acc) {
				break;
			}
			DWORD dwPath = info->suffixOffset - info->localBasePathOffset;
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
		} while (false);

		return flag;
	}

	FILETIME GetCreateTime() const {
		return m_header.createTime;
	}

	FILETIME GetWriteTime() const {
		return m_header.writeTime;
	}

	std::wstring GetLocalPath() const {
		return m_wsPath;
	}

	LNK_FILE() = default;
	~LNK_FILE() = default;

private:
	LNK_HEADER m_header;
	LNK_TID_LIST m_list;
	std::wstring m_wsPath;
};