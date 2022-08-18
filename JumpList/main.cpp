#include <io.h>
#include <iostream>
#include "format.h"

using namespace std;
/*
* Recent access file store at
* C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*
* `cout` may not thread-safe, so please save to file to analysis!
* Warning Just test on Windows 10 / 11!
*/


int main() {

	string basePath = "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*";
	long hFile = 0;
	struct _finddata_t fileInfo;
	hFile = _findfirst(basePath.c_str(), &fileInfo);
	if (hFile == -1) {
		cout << "base path error!" << endl;
		return 0;
	}
	
	FILE* fp = NULL;
	vector<DL_ENTRY> res;
	basePath.pop_back();
	do {
		if (!strcmp(fileInfo.name, ".") ||  !strcmp(fileInfo.name, "..")) {
			continue;
		}
		string name = basePath + fileInfo.name;
		fp = fopen(name.c_str(), "rb");
		if (fp == NULL) {
			return 0;
		}
		fseek(fp, 0, SEEK_END);
		int fileSize = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		char * buffer = new char[fileSize + 1];
		assert(buffer != NULL);
		memset(buffer, 0, fileSize + 1);
		fread(buffer, fileSize, 1, fp);
		
		// start
		JumpList::GetContent(buffer, fileSize, res);
		// Ending ...

		fclose(fp);
		delete[] buffer;
	} while (!_findnext(hFile, &fileInfo));
	cout << "all items number: " << res.size() << endl;
	
	_findclose(hFile);
	system("pause");
	return 0;
}
