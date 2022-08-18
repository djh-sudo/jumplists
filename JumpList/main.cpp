#include <io.h>
#include <iostream>
#include "format.h"

using namespace std;
/*
* Recent access file store at
* C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*
* `cout` may not thread-safe, so please save to file to analysis!
* Just test on Windows 10 / 11
*/


int main() {
	ios::sync_with_stdio(false);
	locale::global(locale(""));
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	bool status = false;
	//
	FILE* fp = NULL;
	fopen_s(&fp, "result.csv", "w, ccs=utf-8");
	if (fp == NULL) {
		return false;
	}
	fwprintf(fp, L"absolute path,create time,modify time,last access time\n");
	//
	string basePath = "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*";
	long hFile = 0;
	struct _finddata_t fileInfo;
	hFile = _findfirst(basePath.c_str(), &fileInfo);
	if (hFile == -1) {
		cout << "base path error!" << endl;
		return 0;
	}
	unsigned int count = 0;
	basePath.pop_back();
	do {
		if (!strcmp(fileInfo.name, ".") ||  !strcmp(fileInfo.name, "..")) {
			continue;
		}
		OLE_OBJECT ole;
		string name = basePath + fileInfo.name;
		status = ole.Init(name);
		if (status == false) {
			continue;
		}
		status = ole.AquireSATChain();
		if (status == false) {
			continue;
		}
		status = ole.GetDirs();
		if (status == false) {
			continue;
		}
		status = ole.AquireSSATChain();
		if (status == false) {
			continue;
		}
		if (status && ole.GetdwDestList() <= 4096) {
			ole.GetDestListFromSSAT();
		}
		else {
			status = ole.GetDestListFromSAT();
		}
		
		for (auto& it : ole.GetdlEntrys()) {
			fwprintf(fp, L"%s,%s,%s,%s\n", it.GetPath().c_str(),
					 converter.from_bytes(it.GetCreateTime()).c_str(),
					 converter.from_bytes(it.GetModifyTime()).c_str(),
					 converter.from_bytes(it.GetLastRecordTime()).c_str());
				     
			++count;
		}
		
	} while (!_findnext(hFile, &fileInfo));
	cout << "all items number: " << count << endl;
	
	_findclose(hFile);
	fclose(fp);
	system("pause");
	return 0;
}
