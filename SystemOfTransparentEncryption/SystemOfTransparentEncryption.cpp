// SystemOfTransparentEncryption.cpp : Определяет точку входа для приложения.
//

#include <windows.h>
#include <tlhelp32.h>
#include <winuser.h>
#include <stdio.h>
#include <wincrypt.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "framework.h"
#include "SystemOfTransparentEncryption.h"
#include "apacheBase64.h"
#include "argon2.h"
#include "aes.hpp"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Argon2RefDll.lib")

#define MAX_LOADSTRING 100

#define SALT_SIZE 16
#define NAME_SIZE 21
#define KEY_SIZE 17 
#define MAX_USERS 10
struct User {
	BYTE name[NAME_SIZE];
	BYTE key[KEY_SIZE];
} users[MAX_USERS];

int userCount = -1;
int currentUser = -1;

// Глобальные переменные:
HINSTANCE hInst;                                // текущий экземпляр
WCHAR szTitle[MAX_LOADSTRING];                  // Текст строки заголовка
WCHAR szWindowClass[MAX_LOADSTRING];            // имя класса главного окна

// Отправить объявления функций, включенных в этот модуль кода:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

VOID ErrorExit(LPCTSTR);
VOID generateSalt(uint8_t*, size_t);
VOID argon2(uint8_t*, uint32_t, uint8_t*, size_t, uint8_t*);
VOID crypt(PBYTE, SIZE_T, uint8_t*, size_t, BOOL);
int toBase64(PBYTE, int, PBYTE);
int fromBase64(PBYTE, PBYTE);
SIZE_T TextFromClipboard(HWND, PBYTE);
VOID TextToClipboard(HWND, PBYTE, SIZE_T);
BOOL CALLBACK TrySendMessage(HWND, LPARAM);
VOID getAndEncryptMessage(HWND);
VOID decryptMessage(HWND);
VOID addNewUser(PBYTE, PBYTE);
INT_PTR CALLBACK addUser(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK selectUser(HWND, UINT, WPARAM, LPARAM);

PBYTE rawText = NULL;
int rawTextSize = 0;
HWND hWnd;
HWND canvas = NULL;

VOID ErrorExit(LPCTSTR lpszFunction) {
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)& lpMsgBuf,
		0, NULL);

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen(lpszFunction) + 40) * sizeof(TCHAR));
	wsprintf((LPWSTR)lpDisplayBuf, TEXT("%s failed with error %d: %s"), lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK | MB_SERVICE_NOTIFICATION);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

VOID generateSalt(uint8_t* salt, size_t saltlen) {
	size_t n = strlen(basis_64);
	for (int i = 0; i < saltlen; i++) {
		salt[i] = basis_64[rand() % n];
	}
}

VOID argon2(uint8_t* pwd, uint32_t pwdlen, uint8_t* salt, size_t saltlen, uint8_t* hash) {
	uint32_t t_cost = 2;            // 1-pass computation
	uint32_t m_cost = (1 << 16);      // 64 mebibytes memory usage
	uint32_t parallelism = 1;       // number of threads and lanes
	
	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash, KEY_SIZE - 1);
}

VOID crypt(PBYTE text, SIZE_T textSize, uint8_t* salt, size_t saltlen, BOOL isEncrypt) {
	uint8_t* key = (uint8_t*)malloc(KEY_SIZE);
	argon2((uint8_t*)users[currentUser].key, KEY_SIZE - 1, salt, saltlen, key);
	const uint8_t* iv = (const uint8_t*)malloc(17);
	strcpy_s((char*)iv, 17, "Mapkn3InitVector");

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	if (isEncrypt) {
		AES_CBC_encrypt_buffer(&ctx, text, textSize);
	}
	else {
		AES_CBC_decrypt_buffer(&ctx, text, textSize);
	}
}

int toBase64(PBYTE rawStr, int rawStrSize, PBYTE base64Str) {
	int base64StrSize = Base64encode_len(rawStrSize);
	if (base64Str != NULL) {
		Base64encode((char*)base64Str, (char*)rawStr, rawStrSize);
	}
	return base64StrSize;
}

int fromBase64(PBYTE base64Str, PBYTE rawStr) {
	int rawStrSize = Base64decode_len((const char*)base64Str);
	if (rawStr != NULL) {
		rawStrSize = Base64decode((char*)rawStr, (const char*)base64Str);
	}
	return rawStrSize;
}

SIZE_T TextFromClipboard(HWND hwnd, PBYTE buffer) {
	UINT nClipboardFormat = CF_TEXT;
	HANDLE pClipboardData = 0;
	PBYTE data = 0;
	SIZE_T dataSize = 0;

	if (IsClipboardFormatAvailable(nClipboardFormat)) {
		if (!OpenClipboard(hwnd)) {
			ErrorExit(TEXT("Open clipboard"));
		}

		pClipboardData = GetClipboardData(nClipboardFormat);
		if (!pClipboardData) {
			CloseClipboard();
			ErrorExit(TEXT("Get clipboard data"));
		} 
		data = (PBYTE)GlobalLock(pClipboardData);
		dataSize = strlen((const char*)data);
		if (buffer != NULL) {
			for (int i = 0; i < dataSize; i++) {
				buffer[i] = data[i];
			}
		}
		GlobalUnlock(pClipboardData);
		if (!CloseClipboard()) {
			ErrorExit(TEXT("Close clipboard"));
		}
	}
	return dataSize;
}

VOID TextToClipboard(HWND hwnd, PBYTE data, SIZE_T dataSize) {
	UINT nClipboardFormat = CF_TEXT;
	HGLOBAL clipboardData = 0;
	PBYTE buffer = 0;

	if (!OpenClipboard(hwnd)) {
		ErrorExit(TEXT("Open clipboard"));
	}
	if (!EmptyClipboard()) {
		ErrorExit(TEXT("Empty clipboard"));
	}
	clipboardData = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, dataSize);
	buffer = (PBYTE)GlobalLock(clipboardData);
	memset(buffer, 0, dataSize);
	for (int i = 0; i < dataSize; i++) {
		buffer[i] = data[i];
	}
	GlobalUnlock(clipboardData);
	SetClipboardData(nClipboardFormat, clipboardData);
	if (!CloseClipboard()) {
		ErrorExit(TEXT("Close clipboard"));
	}
}

BOOL CALLBACK TrySendMessage(HWND hwnd, LPARAM msg) {
	SendMessage(hwnd, msg, 0, 0);
	return TRUE;
}

VOID getAndEncryptMessage(HWND hForeground) {
	PBYTE backUpClipboard = NULL;
	SIZE_T backUpClipboardSize = TextFromClipboard(hForeground, backUpClipboard);
	backUpClipboard = (PBYTE)malloc(backUpClipboardSize);
	memset(backUpClipboard, 0, backUpClipboardSize);
	TextFromClipboard(hForeground, backUpClipboard);

	EnumChildWindows(hForeground, TrySendMessage, WM_CUT);
	PBYTE textFromClipboard = NULL;
	SIZE_T textFromClipboardSize = TextFromClipboard(hForeground, textFromClipboard);
	textFromClipboard = (PBYTE)malloc(textFromClipboardSize);
	memset(textFromClipboard, 0, textFromClipboardSize);
	TextFromClipboard(hForeground, textFromClipboard);

	if (strcmp((const char*)backUpClipboard, (const char*)textFromClipboard) == 0) {
		MessageBox(NULL, TEXT("Выбранный текст совпадает с текстом в буфере обмена"), TEXT("Ошибка"), MB_OK | MB_SERVICE_NOTIFICATION | MB_ICONERROR);
		return;
	}
	if (textFromClipboard != NULL) {
		SIZE_T textSize = textFromClipboardSize;
		if (textFromClipboardSize % 16 != 0) {
			textSize += 16 - (textFromClipboardSize % 16);
		}
		PBYTE text = (PBYTE)malloc(textSize);
		memset(text, 0x00, textSize);
		for (int i = 0; i < textFromClipboardSize; i++) {
			text[i] = textFromClipboard[i];
		}

		uint8_t* salt = (uint8_t*)malloc(SALT_SIZE);
		memset(salt, 0x00, SALT_SIZE);
		generateSalt(salt, SALT_SIZE);

		crypt(text, textSize, salt, SALT_SIZE, TRUE);

		PBYTE base64 = NULL;
		int base64Size = toBase64(text, textSize, base64);
		base64 = (PBYTE)malloc(base64Size);
		memset(base64, 0, base64Size);
		toBase64(text, textSize, base64);

		PBYTE result = NULL;
		int resultSize = base64Size + SALT_SIZE;
		result = (PBYTE)malloc(resultSize);
		memset(result, 0, resultSize);
		int k = 0;
		for (int i = 0; i < SALT_SIZE; i++) {
			result[k++] = salt[i];
		}
		for (int i = 0; i < base64Size; i++) {
			result[k++] = base64[i];
		}
		TextToClipboard(hForeground, result, resultSize);
		EnumChildWindows(hForeground, TrySendMessage, WM_PASTE);
		free(text);
		free(result);

	}
	else {
		MessageBox(NULL, TEXT("Не найден текст в буфере обмена"), TEXT("Информация"), MB_OK | MB_SERVICE_NOTIFICATION | MB_ICONINFORMATION);
	}
	TextToClipboard(hForeground, backUpClipboard, backUpClipboardSize);
	free(textFromClipboard);
	free(backUpClipboard);
}

VOID decryptMessage(HWND hForeground) {
	PBYTE backUpClipboard = NULL;
	SIZE_T backUpClipboardSize = TextFromClipboard(hForeground, backUpClipboard);
	backUpClipboard = (PBYTE)malloc(backUpClipboardSize);
	memset(backUpClipboard, 0, backUpClipboardSize);
	TextFromClipboard(hForeground, backUpClipboard);

	EnumChildWindows(hForeground, TrySendMessage, WM_COPY);
	PBYTE textFromClipboard = NULL;
	SIZE_T textFromClipboardSize = TextFromClipboard(hForeground, textFromClipboard);
	textFromClipboard = (PBYTE)malloc(textFromClipboardSize);
	memset(textFromClipboard, 0, textFromClipboardSize);
	TextFromClipboard(hForeground, textFromClipboard);

	if (strcmp((const char*)backUpClipboard, (const char*)textFromClipboard) == 0) {
		MessageBox(NULL, TEXT("Выбранный текст совпадает с текстом в буфере обмена"), TEXT("Ошибка"), MB_OK | MB_SERVICE_NOTIFICATION | MB_ICONERROR);
		return;
	}
	if (textFromClipboard != NULL) {
		uint8_t* salt = (uint8_t*)malloc(SALT_SIZE);
		memset(salt, 0x00, SALT_SIZE);

		int base64Size = textFromClipboardSize - SALT_SIZE;
		PBYTE base64 = (PBYTE)malloc(base64Size);
		memset(base64, 0, base64Size);
		int k = 0;
		for (int i = 0; i < SALT_SIZE; i++) {
			salt[i] = textFromClipboard[k++];
		}
		for (int i = 0; i < base64Size; i++) {
			base64[i] = textFromClipboard[k++];
		}

		PBYTE text = NULL;
		int textSize = fromBase64(base64, text);
		text = (PBYTE)malloc(textSize);
		memset(text, 0, textSize);
		textSize = fromBase64(base64, text);
		text = (PBYTE)malloc(textSize);
		memset(text, 0, textSize);
		fromBase64(base64, text);

		crypt(text, textSize, salt, SALT_SIZE, FALSE);

		rawTextSize = textSize;
		rawText = (PBYTE)malloc(rawTextSize);
		memset(rawText, 0x00, rawTextSize);
		for (int i = 0; i < rawTextSize; i++) {
			rawText[i] = text[i];
		}

		free(text);

		InvalidateRect(hWnd, NULL, TRUE);
	} else {
		MessageBox(NULL, TEXT("Не найден текст в буфере обмена"), TEXT("Информация"), MB_OK | MB_SERVICE_NOTIFICATION | MB_ICONINFORMATION);
	}
	TextToClipboard(hForeground, backUpClipboard, backUpClipboardSize);
	free(textFromClipboard);
	free(backUpClipboard);
}

VOID addNewUser(PBYTE name, PBYTE key) {
	userCount += 1;
	if (userCount < MAX_USERS) {
		strcpy_s((char*)users[userCount].name, NAME_SIZE, (char*)name);
		strcpy_s((char*)users[userCount].key, KEY_SIZE, (char*)key);
	}
	currentUser += 1;
	if (currentUser == MAX_USERS) {
		currentUser = 0;
	}
	InvalidateRect(hWnd, NULL, TRUE);
 }



int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Разместите код здесь.

    // Инициализация глобальных строк
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_SYSTEMOFTRANSPARENTENCRYPTION, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Выполнить инициализацию приложения:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_SYSTEMOFTRANSPARENTENCRYPTION));

    MSG msg;

	srand(time(NULL));
	if (!RegisterHotKey(NULL, 1, MOD_ALT, 'E')) {
		ErrorExit(TEXT("E: "));
	}
	if (!RegisterHotKey(NULL, 2, MOD_ALT, 'D')) {
		ErrorExit(TEXT("D: "));
	}
	if (!RegisterHotKey(NULL, 3, MOD_ALT, 'N')) {
		ErrorExit(TEXT("N: "));
	}
	if (!RegisterHotKey(NULL, 4, MOD_ALT, 'C')) {
		ErrorExit(TEXT("C: "));
	}
    // Цикл основного сообщения:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
		if (msg.message == WM_HOTKEY) {
			if (userCount == -1 && (msg.wParam == 1 || msg.wParam == 2)) {
				MessageBox(NULL, TEXT("Для начала добавьте собеседника"), TEXT("Предупреждение"), MB_OK | MB_SERVICE_NOTIFICATION | MB_ICONWARNING);
			} else {
				switch (msg.wParam) {
				    case 1:
					    getAndEncryptMessage(GetForegroundWindow());
					    break;
				    case 2:
					    decryptMessage(GetForegroundWindow());
					    break;
					case 3:
						DialogBox(hInst, MAKEINTRESOURCE(IDD_ADD_USER), hWnd, addUser);
						break;
					case 4:
						DialogBox(hInst, MAKEINTRESOURCE(IDD_SELECT_USER), hWnd, selectUser);
						break;
				}
			}
		}

        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

	if (!UnregisterHotKey(NULL, 4)) {
		ErrorExit(TEXT("Un C: "));
	}
	if (!UnregisterHotKey(NULL, 3)) {
		ErrorExit(TEXT("Un N: "));
	}
	if (!UnregisterHotKey(NULL, 2)) {
		ErrorExit(TEXT("Un D: "));
	}
	if (!UnregisterHotKey(NULL, 1)) {
		ErrorExit(TEXT("Un E: "));
	}
    return (int) msg.wParam;
}



//
//  ФУНКЦИЯ: MyRegisterClass()
//
//  ЦЕЛЬ: Регистрирует класс окна.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SYSTEMOFTRANSPARENTENCRYPTION));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_SYSTEMOFTRANSPARENTENCRYPTION);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   ФУНКЦИЯ: InitInstance(HINSTANCE, int)
//
//   ЦЕЛЬ: Сохраняет маркер экземпляра и создает главное окно
//
//   КОММЕНТАРИИ:
//
//        В этой функции маркер экземпляра сохраняется в глобальной переменной, а также
//        создается и выводится главное окно программы.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Сохранить маркер экземпляра в глобальной переменной

   hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, 900, 500, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  ФУНКЦИЯ: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  ЦЕЛЬ: Обрабатывает сообщения в главном окне.
//
//  WM_COMMAND  - обработать меню приложения 
//  WM_PAINT    - Отрисовка главного окна
//  WM_DESTROY  - отправить сообщение о выходе и вернуться
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Разобрать выбор в меню:
            switch (wmId)
            {
			case IDM_ADD_USER:
				DialogBox(hInst, MAKEINTRESOURCE(IDD_ADD_USER), hWnd, addUser);
				break;
			case IDM_SELECT_USER:
				DialogBox(hInst, MAKEINTRESOURCE(IDD_SELECT_USER), hWnd, selectUser);
				break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
		    PBYTE user = NULL;
			size_t userLen = 0;
		    if (userCount >= 0) {
				const char* title = "Текущий собеседник: ";
				int titleLen = strlen(title);
 				int nameLen = 0;
				for (; users[currentUser].name[nameLen] != 0x00; nameLen++) {}
				userLen = titleLen + nameLen;
				user = (PBYTE)malloc(userLen);
				memset(user, 0x00, userLen);
				
				for (int i = 0; i < titleLen; i++) {
					user[i] = title[i];
				}
				for (int i = 0; i < nameLen; i++) {
					user[titleLen + i] = users[currentUser].name[i];
				}
			}
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hWnd, &ps);
			if (user != NULL) {
				TextOutA(hdc, 10, 10, (LPCSTR)user, userLen);
			}
			TextOutA(hdc, 10, 40, (LPCSTR)rawText, rawTextSize);
			EndPaint(hWnd, &ps);
			free(user);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Обработчик сообщений для окна "О программе".
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

INT_PTR CALLBACK addUser(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	PCHAR lpszKey = (PCHAR)malloc(KEY_SIZE);
	memset(lpszKey, 0x00, KEY_SIZE);
	BYTE cchKey;

	PCHAR lpszName = (PCHAR)malloc(NAME_SIZE);
	memset(lpszName, 0x00, NAME_SIZE);
	BYTE cchName;

	switch (message)
	{
	case WM_INITDIALOG: 
		// Set the default push button to "Cancel." 
		SendMessage(hDlg,
			DM_SETDEFID,
			(WPARAM)IDCANCEL,
			(LPARAM)0);

		return (INT_PTR)TRUE;

	case WM_COMMAND:
		// Set the default push button to "OK" when the user enters text. 
		if (HIWORD(wParam) == EN_CHANGE &&
			LOWORD(wParam) == IDC_KEY_EDIT)
		{
			SendMessage(hDlg,
				DM_SETDEFID,
				(WPARAM)IDOK,
				(LPARAM)0);
		}
		switch (wParam)
		{
		case IDOK:
			// Get number of characters. 
			cchKey = (BYTE)SendDlgItemMessage(hDlg,
				IDC_KEY_EDIT,
				EM_LINELENGTH,
				(WPARAM)0,
				(LPARAM)0);
			if (cchKey != KEY_SIZE - 1)
			{
				MessageBox(hDlg,
					L"Длина пароля должна быть 16 символов",
					L"Ошибка",
					MB_OK | MB_ICONERROR);

				//EndDialog(hDlg, TRUE);
				return (INT_PTR)FALSE;
			}

			// Put the number of characters into first word of buffer. 
			*((LPBYTE)lpszKey) = cchKey;

			// Get the characters. 
			SendDlgItemMessageA(hDlg,
				IDC_KEY_EDIT,
				EM_GETLINE,
				(WPARAM)0,
				(LPARAM)lpszKey);

			// Get number of characters. 
			cchName = (BYTE)SendDlgItemMessage(hDlg,
				IDC_NAME_EDIT,
				EM_LINELENGTH,
				(WPARAM)0,
				(LPARAM)0);
			if (cchName > NAME_SIZE - 1)
			{
				MessageBox(hDlg,
					L"Длина имени должна быть 20 символов",
					L"Ошибка",
					MB_OK | MB_ICONERROR);

				//EndDialog(hDlg, TRUE);
				return (INT_PTR)FALSE;
			}

			// Put the number of characters into first word of buffer. 
			*((LPBYTE)lpszName) = cchName;

			// Get the characters. 
			SendDlgItemMessageA(hDlg,
				IDC_NAME_EDIT,
				EM_GETLINE,
				(WPARAM)0,
				(LPARAM)lpszName);

			addNewUser((PBYTE)lpszName, (PBYTE)lpszKey);

			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;

		case IDCANCEL:
			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;
		}
		return 0;
	}
	return (INT_PTR)FALSE;

	UNREFERENCED_PARAMETER(lParam);
}

INT_PTR CALLBACK selectUser(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
		BYTE name[NAME_SIZE];
		for (int i = 0; i <= userCount; i++) {
			memset(name, 0x00, NAME_SIZE);
			strcpy_s((char*)name, NAME_SIZE, (char*)users[i].name);
			SendDlgItemMessageA(hDlg, IDC_USER_COMBO, CB_ADDSTRING, 0, (LPARAM)name);
		}
		SendDlgItemMessage(hDlg, IDC_USER_COMBO, CB_SETCURSEL, currentUser, 0);
		// Set the default push button to "Cancel." 
		SendMessage(hDlg,
			DM_SETDEFID,
			(WPARAM)IDCANCEL,
			(LPARAM)0);

		return (INT_PTR)TRUE;

	case WM_COMMAND:
		// Set the default push button to "OK" when the user enters text. 
		if (HIWORD(wParam) == CBN_SELCHANGE)
		{
			SendMessage(hDlg,
				DM_SETDEFID,
				(WPARAM)IDOK,
				(LPARAM)0);
		}
		switch (wParam)
		{
		case IDOK:
			currentUser = SendDlgItemMessageA(hDlg, IDC_USER_COMBO, CB_GETCURSEL, 0, 0);
			InvalidateRect(hWnd, NULL, TRUE);

			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;

		case IDCANCEL:
			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;
		}
		return 0;
	}
	return (INT_PTR)FALSE;

	UNREFERENCED_PARAMETER(lParam);
}
