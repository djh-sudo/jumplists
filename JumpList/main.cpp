#include <io.h>
#include <iostream>
#include "format.h"

using namespace std;
/*
* Recent access file store at
* C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*
*/

int main() {
	
	bool status = false;
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
		if (status && ole.GetdwDestList() <= 4096) {
			ole.AquireSSATChain();
			ole.GetDestListFromSSAT();
		}
		else {
			status = ole.GetDestListFromSAT();
		}
		wcout.imbue(locale("chs"));
		cout << fileInfo.name << ":" << endl;
		for (auto& it : ole.GetdlEntrys()) {
			cout << "\tlastAccess: " << it.GetLastRecordTime() << endl;
			wcout << "\tpath: " << it.GetPath() << endl;
			++count;
		}
		
	} while (!_findnext(hFile, &fileInfo));
	cout << "all items number: " << count << endl;
	
	_findclose(hFile);
	system("pause");
	return 0;
}
