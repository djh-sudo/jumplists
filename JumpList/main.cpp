#include <iostream>
#include "format.h"

using namespace std;


int main() {

	OLE_OBJECT ole;
	ole.Init("C:/Users/%username%/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms");
	ole.AquireSATChain();
	ole.GetDirs();
	ole.GetDestList();

	wcout.imbue(locale("chs"));
	for (auto& it : ole.GetdlEntrys()){
		cout << "lastAccess: " << it.GetLastRecordTime() << endl;
		wcout << "path: " << it.GetPath() << endl;
	}
	system("pause");
	return 0;
}
