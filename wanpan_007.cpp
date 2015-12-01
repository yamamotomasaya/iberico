#include "stdafx.h"
#include <Shlwapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <iomanip>			// for std::setw, std::setfill>
#define  hexformat(fill, wd)    std::hex<<std::setfill(fill)<<std::setw(wd)

using namespace std;

typedef LONG(WINAPI *TNtReadVirtualMemory )(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *TNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
TNtReadVirtualMemory pfnNtReadVirtualMemory = nullptr;
TNtWriteVirtualMemory pfnNtWriteVirtualMemory = nullptr;

const UINT SEARCH_STA_ADDR	= 0x00000000;	// サーチ開始アドレス
const UINT SEARCH_END_ADDR	= 0x5FFFFFFF;	// サーチ終了アドレス
const int SEARCH_TARGET		= 0x15;			// 戦闘中か否か[0x15:非戦闘中、not 0x15:戦闘中]
const int BUFFER_SIZE		= 0x8000;
const int WAIT_TIME			= 10;

HANDLE pHandle;

// iniファイル関連
const char INI_FILE[] = "./wanpan.ini";
int sleep_time_ini = 4000;
int battle_wait_time_ini = 5000;
int auto_battle_ini = 0;
int result_cancel_ini = 0;

UINT search(unsigned char bytecode[], int n, bool checkhex) {
	// サーチ開始アドレス
	UINT start = SEARCH_STA_ADDR;
	int a = 0;
	CHAR *MemoryBuff = new CHAR[BUFFER_SIZE];
	while (start <= SEARCH_END_ADDR) {
		pfnNtReadVirtualMemory(pHandle, (LPVOID)start, (LPVOID)MemoryBuff, BUFFER_SIZE, nullptr);
		for (int i = 0; i < BUFFER_SIZE; i += 4) {	// バッファのサイズ=ループ回数
			start += 4; MemoryBuff += 4;
			if (memcmp(MemoryBuff, bytecode, n) == 0) {
				if (checkhex == true) {
					//addr = start - 0x208;	// Ver 5.2.0-5.2.1
					//addr = start - 0x224;	// Ver 5.3.0
					pfnNtReadVirtualMemory(pHandle, (LPVOID)(start - 0x224), &a, 4, nullptr);
					if (a == 0xFFFFFFFF) {
						return start;
					}
				}
				else {
					return start;
				}
			}
		}
		MemoryBuff -= BUFFER_SIZE; //ポインタを戻しておきます。
	}
	delete[] MemoryBuff;
	return 0;
}

DWORD SearchProcesses() {
	HANDLE hSnap;
	PROCESSENTRY32 pe;
	DWORD dwProcessIdLast[4];
	BOOL bResult;
	int i, no;

	try {
		if ((hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
			throw "CreateToolhelp32Snapshot";
		}

		i = 0;
		pe.dwSize = sizeof(pe);
		bResult = Process32First(hSnap, &pe);

		while (bResult) {
			if (!lstrcmpi(pe.szExeFile, "NoxVMHandle.exe")) {
				if (i == 0) {
					cout << "\n" << "PID List" << "\n";
				}

				dwProcessIdLast[i] = pe.th32ProcessID;

				i++;
				cout << i << "：" << std::hex << dwProcessIdLast[i - 1] << endl;
			}
			bResult = Process32Next(hSnap, &pe);
		}

		while (true) {
			cout << "モンストを起動後、PIDの番号を入力してください。" << "\n";
			cin >> no;

			if (cin.good() == 0) {
				cout << "整数値以外のPIDが入力された。" << "\n";
				cin.clear();
				cin.seekg(0);
				continue;
			}
			else {
				if (no < 1 || no > i) {
					cout << "正しいPIDの番号を入力してください。" << "\n";
					cin.clear();
					cin.seekg(0);
					continue;
				}
				break;
			}
		}
	}
	catch (char* str) {
		cout << "error:" << str << "\n";
	}

	return dwProcessIdLast[no - 1];
}

void Init() {	// iniファイルより各々の設定情報を取得する
	sleep_time_ini = GetPrivateProfileInt("Option", "SleepTime", 4000, INI_FILE);
	//cout << "sleep_time = " << sleep_time_ini << endl;
	battle_wait_time_ini = GetPrivateProfileInt("Option", "BattleWaitTime", 5000, INI_FILE);
	//cout << "battle_wait_time = " << battle_wait_time_ini << endl;
	auto_battle_ini = GetPrivateProfileInt("Option", "AutoBattle", 1, INI_FILE);
	//cout << "AutoBattle = " << auto_battle_ini << endl;
	result_cancel_ini = GetPrivateProfileInt("Option", "ResultCancel", 0, INI_FILE);
	//cout << "ResultCancel = " << result_cancel_ini << endl;
}
int main()
{
	cout << "*** ワンパン君 ***" << "\n";
	cout << "初版：はなたろうと愉快な仲間たち" << "\n";
	cout << "３版：2chの愉快な仲間たち" << "\n";

	pfnNtReadVirtualMemory = (TNtReadVirtualMemory)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtReadVirtualMemory");
	pfnNtWriteVirtualMemory = (TNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtWriteVirtualMemory");

	// 初期処理
	Init();

	// Process一覧を表示する
	DWORD pID = SearchProcesses();
	int base_addr0 = 0;
	int base_addr1 = 0;
	int base_addr2 = 0;

	try
	{
		if ((pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID)) == NULL) {
			throw "OpenProcess";
		}

		unsigned char bytecode0[] = { 0x8F, 0xC2, 0xF5, 0x3F, 0x00, 0x00, 0x00, 0x40 };
		unsigned char bytecode1[] = { 0x38, 0x29, 0x68, 0x14 };
		unsigned char bytecode2[] = { 0xD0, 0x0F, 0x01, 0x00, 0x15, 0xCD, 0x5B, 0x07, 0xE5, 0x55, 0x9A, 0x15, 0xB5, 0x3B, 0x12, 0x1F, 0x33, 0x13, 0x49, 0x05 };

		// 自動弾きのアドレス取得
		while (!(base_addr1 = search(bytecode1, sizeof bytecode1, false))) {
			Sleep(WAIT_TIME);
		}
		if (auto_battle_ini) {
			cout << "auto_play start.     [0x" << hexformat('0', 8) << base_addr1 << "]\n";
		}
		//cout << "base_addr1 [0x" << std::hex << base_addr1 << "]\n";

		// リザルトキャンセルのアドレス取得
		while (!(base_addr2 = search(bytecode2, sizeof bytecode2, false))) {
			Sleep(WAIT_TIME);
		}
		if (result_cancel_ini) {
			cout << "result_cancel start. [0x" << std::hex << base_addr2 << "]\n";
		}
		//cout << "base_addr2 [0x" << std::hex << base_addr2 << "]\n";
		cout << "init ok." << "\n";

		int battle_count = 0;
		int search_target = SEARCH_TARGET;
		bool battle_message = false;

		while (true) {
			// 戦闘中か否か判定
			while (search_target == SEARCH_TARGET) {
				pfnNtReadVirtualMemory(pHandle, (void*)(base_addr2 + 0x4), &search_target, 1, nullptr);
				Sleep(WAIT_TIME);
			}

			// 戦闘画面遷移までn秒待機
			Sleep(battle_wait_time_ini);

			// 友情コンボのアドレスを取得
			while (!(base_addr0 = search(bytecode0, sizeof bytecode0, true))) {
				cout << "base_addr0 [0x" << hexformat('0', 8) << base_addr0 << "]\n";
				Sleep(WAIT_TIME);
			}

			int yujo_kind_value		= 35;	// 友情コンボの種類 35:フラッシュ
			int yujo_power_value	= 0;	// 暗号化された友情コンボの威力

			int auto_battle_value	= 1056964508;	// 0x3EFFFF9C
			int result_cancel_value = 0;

			// ***** Ver 5.2.0-5.2.1 *****
			//int addr1 = addr0 - 0x1f8;	// 友情コンボの種類
			//int addr2 = addr0 - 0x1e0;	// 友情コンボのスイッチ
			//int addr3 = addr0 - 0x1c0;	// 暗号化された友情コンボの威力
			//int addr4 = addr0 - 0x208;	// ストッパーAddr
			// ***** Ver 5.2.0-5.2.1 *****

			// ***** Ver 5.3.0- *****
			int yujo_kind_addr		= base_addr0 - 0x214;	// 友情コンボの種類
			int yujo_switch_addr	= base_addr0 - 0x1fc;	// 友情コンボのスイッチ
			int yujo_power_addr		= base_addr0 - 0x1dc;	// 暗号化された友情コンボの威力
			int stopper_addr		= base_addr0 - 0x224;	// ストッパーAddr

			int auto_battle_addr	= base_addr1 + (0x4B8);	// 自動弾き
			int result_cancel_addr	= base_addr2 + (0x14);	// リザルトキャンセル
			// ***** Ver 5.3.0- *****

			// 暗号化された友情コンボの威力を読み込んで「１」を加算する
			pfnNtReadVirtualMemory(pHandle, (void*)(yujo_power_addr), &yujo_power_value, 4, nullptr);
			yujo_power_value++;

			battle_count++;
			cout << "battle start.        [0x" << hexformat('0', 8) << base_addr0 << "] (" << std::dec << battle_count << ")\n";
			battle_message = true;

			// 戦闘中であれば、以下の処理を行なう
			while (search_target != SEARCH_TARGET) {
				// 友情コンボ発動
				int yujo_switch_value = 1;	// 友情コンボのスイッチ[0:off 1:on]
				pfnNtWriteVirtualMemory(pHandle, (void*)(yujo_kind_addr), &yujo_kind_value, sizeof yujo_kind_value, nullptr);
				pfnNtWriteVirtualMemory(pHandle, (void*)(yujo_switch_addr), &yujo_switch_value, sizeof yujo_switch_value, nullptr);
				pfnNtWriteVirtualMemory(pHandle, (void*)(yujo_power_addr), &yujo_power_value, sizeof yujo_power_value, nullptr);

				if (auto_battle_ini) {
					// 自動弾き
					pfnNtWriteVirtualMemory(pHandle, (void*)(auto_battle_addr), &auto_battle_value, sizeof auto_battle_value, nullptr);
				}

				if (result_cancel_ini) {
					pfnNtReadVirtualMemory(pHandle, (void*)(result_cancel_addr), &result_cancel_value, sizeof result_cancel_value, nullptr);
					if (result_cancel_value >= 2) {
						// リザルトキャンセル
						result_cancel_value = 1;
						pfnNtWriteVirtualMemory(pHandle, (void*)(result_cancel_addr), &result_cancel_value, sizeof result_cancel_value, nullptr);
					}
				}
				Sleep(sleep_time_ini);
				pfnNtReadVirtualMemory(pHandle, (void*)(base_addr2 + 0x4), &search_target, 1, nullptr);
				//cout << "search_target [0x" << std::hex << search_target << "]\n";
			}
			if (battle_message) {
				base_addr0 = 0;
				cout << "battle end." << "\n";
			}
		}
	}
	catch (char* str) {
		cout << "error:" << str << "\n";
	}
}