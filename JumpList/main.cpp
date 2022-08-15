#include <iostream>
#include "format.h"

using namespace std;


int main() {

	OLE_OBJECT ole;
	ole.Init("../test/579438f135536aec.automaticDestinations-ms");
	ole.AquireSATChain();
	ole.GetDirs();
	ole.GetDestList();

	wcout.imbue(locale("chs"));
	unsigned int count = 0;
	for (auto& it : ole.GetdlEntrys()){
		cout << "lastAccess: " << it.GetLastRecordTime() << endl;
		wcout << "path: " << it.GetPath() << endl;
		++count;
	}
	cout << "all items number: " << count << endl;
	system("pause");
	return 0;
}
