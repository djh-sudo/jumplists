#include <iostream>
#include <cstdlib>
#include <vector>
#include <locale>
#include "OLECF.h"

using namespace std;

int main(int argc,char* argv[]) {
	/*
	 * 2022-08-03
	 * testing program
	*/
	// ../test/75f3ef23c86a992c.automaticDestinations-ms
	// ../test/7c51ad1c9b4d7eb5.automaticDestinations-ms
	// ../test/5f7b5f1e01b83767.automaticDestinations-ms
	// ../test/579438f135536aec.automaticDestinations-ms
	FILE *fp = fopen("../test/579438f135536aec.automaticDestinations-ms", "rb");
	assert(fp);
	
	fseek(fp, 0, SEEK_END);
	DWORD size =  ftell(fp);
	fseek(fp, 0, SEEK_SET);
	BYTE * memoryBuufer = new BYTE[size];
	assert(memoryBuufer);
	memset(memoryBuufer, 0, size);
	fread(memoryBuufer, size, 1, fp);
	
	/* core code */
	vector<DL_ENTRY>res;
	// Call API
	OLE_OBJECT::GetContent(memoryBuufer, size, res);
	// output the result
	wcout.imbue(locale("chs"));
	for (auto &it : res) {
		cout << "last access time: " << it.GetLastRecordTime() << endl;
		wcout << "ab path: " << it.GetPath() << endl;
	}
	/* end of core code */

	delete[] memoryBuufer;
	fclose(fp);
	system("pause");
	return 0;
}