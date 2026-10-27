
// --------------------------------------------------------------
//
//  Thinkpad Fan Control
//
// --------------------------------------------------------------
//
//	This program and source code is in the public domain.
//
//	The author claims no copyright, copyleft, license or
//	whatsoever for the program itself (with exception of
//	WinIO driver).  You may use, reuse or distribute it's 
//	binaries or source code in any desired way or form,  
//	Useage of binaries or source shall be entirely and 
//	without exception at your own risk. 
// 
// --------------------------------------------------------------
#include "_prec.h"
#include "tools.h"
#include "fancontrol.h"
#include <taskschd.h>
#include <sddl.h>
#include <comdef.h>
#include <wrl/client.h>
#include <string>
#include <vector>
#include <new>
#include <memory>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
using Microsoft::WRL::ComPtr;

struct StartupComApartment {
	HRESULT result;
	StartupComApartment() : result(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)) {}
	~StartupComApartment() { if (SUCCEEDED(result)) CoUninitialize(); }
};

std::wstring EscapeTaskXml(const std::wstring& value) {
	std::wstring escaped;
	for (wchar_t ch : value) {
		switch (ch) {
		case L'&': escaped += L"&amp;"; break;
		case L'<': escaped += L"&lt;"; break;
		case L'>': escaped += L"&gt;"; break;
		case L'\"': escaped += L"&quot;"; break;
		case L'\'': escaped += L"&apos;"; break;
		default: escaped += ch; break;
		}
	}
	return escaped;
}

// Query (-1), remove (0), or create/update (1) this user's startup task.
HRESULT StartupTask(int operation, bool& enabled) {
	enabled = false;
	try {
		StartupComApartment apartment;
		if (FAILED(apartment.result) && apartment.result != RPC_E_CHANGED_MODE)
			return apartment.result;
		HRESULT hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (FAILED(hr) && hr != RPC_E_TOO_LATE) return hr;

		// Scope the task and logon trigger to the current Windows user.
		HANDLE token = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
			return HRESULT_FROM_WIN32(GetLastError());
		DWORD size = 0;
		GetTokenInformation(token, TokenUser, NULL, 0, &size);
		if (!size) {
			DWORD error = GetLastError();
			CloseHandle(token);
			return HRESULT_FROM_WIN32(error);
		}
		// Allocate without throwing while the token handle is held.
		std::unique_ptr<BYTE[]> user(new (std::nothrow) BYTE[size]);
		if (!user) { CloseHandle(token); return E_OUTOFMEMORY; }
		BOOL gotUser = GetTokenInformation(token, TokenUser, user.get(), size, &size);
		DWORD error = GetLastError();
		CloseHandle(token);
		if (!gotUser) return HRESULT_FROM_WIN32(error);
		LPWSTR sidText = NULL;
		if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.get())->User.Sid, &sidText))
			return HRESULT_FROM_WIN32(GetLastError());
		std::unique_ptr<wchar_t, decltype(&LocalFree)> sidOwner(sidText, &LocalFree);
		_bstr_t sid(sidText);
		std::wstring taskName = L"TPFanCtrl2-Startup-";
		taskName += static_cast<const wchar_t*>(sid);

		ComPtr<ITaskService> service;
		hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
			IID_PPV_ARGS(service.GetAddressOf()));
		if (FAILED(hr)) return hr;
		hr = service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
		if (FAILED(hr)) return hr;
		ComPtr<ITaskFolder> folder;
		hr = service->GetFolder(_bstr_t(L"\\"), folder.GetAddressOf());
		if (FAILED(hr)) return hr;

		if (operation == -1) {
			ComPtr<IRegisteredTask> task;
			hr = folder->GetTask(_bstr_t(taskName.c_str()), task.GetAddressOf());
			if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return S_OK;
			if (FAILED(hr)) return hr;
			VARIANT_BOOL taskEnabled = VARIANT_FALSE;
			hr = task->get_Enabled(&taskEnabled);
			enabled = SUCCEEDED(hr) && taskEnabled == VARIANT_TRUE;
			return hr;
		}
		if (operation == 0) {
			hr = folder->DeleteTask(_bstr_t(taskName.c_str()), 0);
			return hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ? S_OK : hr;
		}

		std::vector<wchar_t> path(32768);
		DWORD length = GetModuleFileNameW(NULL, path.data(), static_cast<DWORD>(path.size()));
		if (!length) return HRESULT_FROM_WIN32(GetLastError());
		if (length >= path.size()) return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
		std::wstring executable(path.data(), length);
		size_t slash = executable.find_last_of(L"\\/");
		if (slash == std::wstring::npos) return E_INVALIDARG;
		std::wstring xml =
			L"<Task version=\"1.3\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
			L"<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" +
			std::wstring(static_cast<const wchar_t*>(sid)) +
			L"</UserId></LogonTrigger></Triggers><Principals><Principal id=\"User\"><UserId>" +
			std::wstring(static_cast<const wchar_t*>(sid)) +
			L"</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel>"
			L"</Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
			L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
			L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
			L"<StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled>"
			L"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>"
			L"<Actions Context=\"User\"><Exec><Command>" + EscapeTaskXml(executable) +
			L"</Command><WorkingDirectory>" + EscapeTaskXml(executable.substr(0, slash + 1)) +
			L"</WorkingDirectory></Exec></Actions></Task>";
		ComPtr<IRegisteredTask> registeredTask;
		hr = folder->RegisterTask(_bstr_t(taskName.c_str()), _bstr_t(xml.c_str()),
			TASK_CREATE_OR_UPDATE, _variant_t(static_cast<const wchar_t*>(sid)), _variant_t(),
			TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), registeredTask.GetAddressOf());
		enabled = SUCCEEDED(hr);
		return hr;
	}
	catch (const _com_error& error) { return error.Error(); }
	catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
}
}

void FANCONTROL::RefreshStartupCheckbox() {
	bool enabled = false;
	HRESULT hr = StartupTask(-1, enabled);
	::CheckDlgButton(this->hwndDialog, 8400,
		FAILED(hr) ? BST_INDETERMINATE : (enabled ? BST_CHECKED : BST_UNCHECKED));
	if (FAILED(hr)) {
		char message[128];
		sprintf_s(message, "Unable to read startup setting (0x%08lx).", static_cast<unsigned long>(hr));
		this->Trace(message);
	}
}

void FANCONTROL::SetStartupFromCheckbox() {
	bool requested = ::IsDlgButtonChecked(this->hwndDialog, 8400) == BST_CHECKED;
	bool enabled = false;
	HRESULT hr = StartupTask(requested ? 1 : 0, enabled);
	if (FAILED(hr)) {
		char message[256];
		sprintf_s(message, "Unable to change the startup setting (0x%08lx). Run TPFanControl as administrator and try again.",
			static_cast<unsigned long>(hr));
		this->Trace(message);
		::MessageBox(this->hwndDialog, message, "TPFanControl", MB_OK | MB_ICONERROR);
	}
	else {
		this->Trace(requested ? "Startup enabled for this Windows user." : "Startup disabled for this Windows user.");
	}
	this->RefreshStartupCheckbox();
}


//-------------------------------------------------------------------------
//  read config file
//-------------------------------------------------------------------------
int
FANCONTROL::ReadConfig(const char* configfile)
{
	char buf[1024];

	int i, ok = false, lcnt1 = 0, lcnt2 = 0;

	int ProcessPriority = 2;

	strncpy_s(this->MenuLabelSM1, sizeof(this->MenuLabelSM1), "Smart Level 1", 14);
	strncpy_s(this->MenuLabelSM2, sizeof(this->MenuLabelSM2), "Smart Level 2", 14);

	setzero(SensorOffset, sizeof(SensorOffset));
	setzero(FSensorOffset, sizeof(FSensorOffset));

	this->State.Fan1SpeedHi = 0x00;
	this->State.Fan1SpeedLo = 0x00;
	this->State.Fan2SpeedHi = 0x00;
	this->State.Fan2SpeedLo = 0x00;

	this->fan1speed = 0;
	this->fan2speed = 0;

	this->IndSmartLevel = 0;

	//
	// read from file
	//
	FILE* f;
	errno_t errf = fopen_s(&f, configfile, "r");
	if (!errf) {
		while (!feof(f)) {
			strcpy_s(buf, sizeof(buf), "");

			fgets(buf, sizeof(buf), f);

			if (buf[0] == '/' || buf[0] == '#' || buf[0] == ';')
				continue;

			if (_strnicmp(buf, "UseTWR=", 7) == 0) {
				this->UseTWR = atoi(buf + 7);
				continue;
			}

			if (_strnicmp(buf, "Active=", 7) == 0) {
				this->ActiveMode = atoi(buf + 7);
				continue;
			}

			if (_strnicmp(buf, "ManFanSpeed=", 12) == 0) {
				this->ManFanSpeed = atoi(buf + 12);
				continue;
			}

			if (_strnicmp(buf, "ProcessPriority=", 16) == 0) {
				ProcessPriority = atoi(buf + 16);
				continue;
			}

			if (_strnicmp(buf, "cycle=", 6) == 0) {
				this->Cycle = atoi(buf + 6);
				continue;
			}
			
			if (_strnicmp(buf, "IconCycle=", 10) == 0) {
				this->IconCycle = atoi(buf + 10);
				continue;
			}

			if (_strnicmp(buf, "ReIcCycle=", 10) == 0) {
				this->ReIcCycle = atoi(buf + 10);
				continue;
			}

			if (_strnicmp(buf, "IconFontSize=", 13) == 0) {
				this->iFontIconB = atoi(buf + 13);
				continue;
			}

			if (_strnicmp(buf, "MenuLabelSM1=", 13) == 0) {
				char* p = buf + 13, * p2 = this->MenuLabelSM1;
				while (*p != '/') {	// copy until '/' excluding tab, carr ret, new line
					if (*p != '\t' && *p != '\r' && *p != '\n')
						*p2++ = *p;
					p++;
				}
				*p2 = '\0';
				continue;
			}

			if (_strnicmp(buf, "MenuLabelSM2=", 13) == 0) {
				char* p = buf + 13, * p2 = this->MenuLabelSM2;
				while (*p != '/') {	// copy until '/' excluding tab, carr ret, new line
					if (*p != '\t' && *p != '\r' && *p != '\n')
						*p2++ = *p;
					p++;
				}
				*p2 = '\0';
				continue;
			}

			if (_strnicmp(buf, "FanSpeedLowByte=", 16) == 0) {
				this->FanSpeedLowByte = atoi(buf + 16);
				continue;
			}

			if (_strnicmp(buf, "NoExtSensor=", 12) == 0) {
				this->NoExtSensor = atoi(buf + 12);
				continue;
			}

			if (_strnicmp(buf, "SlimDialog=", 11) == 0) {
				this->SlimDialog = atoi(buf + 11);
				if (this->SlimDialog != 0) 
					this->SlimDialog = 1;
				continue;
			}

			if (_strnicmp(buf, "level=", 6) == 0) {
				sscanf_s(buf + 6, "%d %d %d %d", &this->SmartLevels[lcnt1].temp, &this->SmartLevels[lcnt1].fan, &this->SmartLevels[lcnt1].hystUp, &this->SmartLevels[lcnt1].hystDown);
				sscanf_s(buf + 6, "%d %d %d %d", &this->SmartLevels1[lcnt1].temp1, &this->SmartLevels1[lcnt1].fan1, &this->SmartLevels1[lcnt1].hystUp1, &this->SmartLevels1[lcnt1].hystDown1);
				lcnt1++;
				continue;
			}

			if (_strnicmp(buf, "level2=", 7) == 0) {
				sscanf_s(buf + 7, "%d %d %d %d", &this->SmartLevels2[lcnt2].temp2, &this->SmartLevels2[lcnt2].fan2, &this->SmartLevels2[lcnt2].hystUp2, &this->SmartLevels2[lcnt2].hystDown2);
				lcnt2++;
				continue;
			}

			if (_strnicmp(buf, "fanbeep=", 8) == 0) {
				sscanf_s(buf + 8, "%d %d", &this->FanBeepFreq, &this->FanBeepDura);
				continue;
			}

			if (_strnicmp(buf, "iconlevels=", 11) == 0) {
				sscanf_s(buf + 11, "%d %d %d", &this->IconLevels[0], &this->IconLevels[1], &this->IconLevels[2]);
				continue;
			}

			if (_strnicmp(buf, "NoWaitMessage=", 14) == 0) {
				this->NoWaitMessage = atoi(buf + 14);
				continue;
			}

			if (_strnicmp(buf, "StartMinimized=", 15) == 0) {
				this->StartMinimized = atoi(buf + 15);
				continue;
			}

			if (_strnicmp(buf, "NoBallons=", 10) == 0) {
				this->NoBallons = atoi(buf + 10);
				continue;
			}

			if (_strnicmp(buf, "HK_BIOS=", 8) == 0) {
				this->HK_BIOS_Method = buf[8] - 0x30;
				this->HK_BIOS = buf[10];
				if ((this->HK_BIOS == 0x46) && (buf[11] > 0x30) && (buf[11] < 0x40)) 
					this->HK_BIOS = 0x70 + atoi(buf + 11) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_Manual=", 10) == 0) {
				this->HK_Manual_Method = buf[10] - 0x30;
				this->HK_Manual = buf[12];
				if ((this->HK_Manual == 0x46) && (buf[13] > 0x30) && (buf[13] < 0x40)) 
					this->HK_Manual = 0x70 + atoi(buf + 13) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_Smart=", 9) == 0) {
				this->HK_Smart_Method = buf[9] - 0x30;
				this->HK_Smart = buf[11];
				if ((this->HK_Smart == 0x46) && (buf[12] > 0x30) && (buf[12] < 0x40))
					this->HK_Smart = 0x70 + atoi(buf + 12) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_SM1=", 7) == 0) {
				this->HK_SM1_Method = buf[7] - 0x30;
				this->HK_SM1 = buf[9];
				if ((this->HK_SM1 == 0x46) && (buf[10] > 0x30) && (buf[10] < 0x40))
					this->HK_SM1 = 0x70 + atoi(buf + 10) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_SM2=", 7) == 0) {
				this->HK_SM2_Method = buf[7] - 0x30;
				this->HK_SM2 = buf[9];
				if ((this->HK_SM2 == 0x46) && (buf[10] > 0x30) && (buf[10] < 0x40))
					this->HK_SM2 = 0x70 + atoi(buf + 10) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_TG_BS=", 9) == 0) {
				this->HK_TG_BS_Method = buf[9] - 0x30;
				this->HK_TG_BS = buf[11];
				if ((this->HK_TG_BS == 0x46) && (buf[12] > 0x30) && (buf[12] < 0x40))
					this->HK_TG_BS = 0x70 + atoi(buf + 12) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_TG_BM=", 9) == 0) {
				this->HK_TG_BM_Method = buf[9] - 0x30;
				this->HK_TG_BM = buf[11];
				if ((this->HK_TG_BM == 0x46) && (buf[12] > 0x30) && (buf[12] < 0x40))
					this->HK_TG_BM = 0x70 + atoi(buf + 12) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_TG_MS=", 9) == 0) {
				this->HK_TG_MS_Method = buf[9] - 0x30;
				this->HK_TG_MS = buf[11];
				if ((this->HK_TG_MS == 0x46) && (buf[12] > 0x30) && (buf[12] < 0x40))
					this->HK_TG_MS = 0x70 + atoi(buf + 12) - 1;
				continue;
			}

			if (_strnicmp(buf, "HK_TG_12=", 9) == 0) {
				this->HK_TG_12_Method = buf[9] - 0x30;
				this->HK_TG_12 = buf[11];
				if ((this->HK_TG_12 == 0x46) && (buf[12] > 0x30) && (buf[12] < 0x40))
					this->HK_TG_12 = 0x70 + atoi(buf + 12) - 1;
				continue;
			}

			if (_strnicmp(buf, "IconColorFan=", 13) == 0) {
				this->IconColorFan = atoi(buf + 13);
				continue;
			}

			if (_strnicmp(buf, "Lev64Norm=", 10) == 0) {
				this->Lev64Norm = atoi(buf + 10);
				continue;
			}

			if (_strnicmp(buf, "BluetoothEDR=", 13) == 0) {
				this->BluetoothEDR = atoi(buf + 13);
				continue;
			}

			if (_strnicmp(buf, "ManModeExit=", 12) == 0) {
				this->ManModeExit = atoi(buf + 12);
				continue;
			}

			if (_strnicmp(buf, "ShowBiasedTemps=", 16) == 0) {
				this->ShowBiasedTemps = atoi(buf + 16);
				continue;
			}

			if (_strnicmp(buf, "MaxReadErrors=", 14) == 0) {
				this->MaxReadErrors = atoi(buf + 14);
				continue;
			}

			if (_strnicmp(buf, "SecWinUptime=", 13) == 0) {
				this->SecWinUptime = atoi(buf + 13);
				continue;
			}

			if (_strnicmp(buf, "SecStartDelay=", 14) == 0) {
				this->SecStartDelay = atoi(buf + 14);
				continue;
			}

			if (_strnicmp(buf, "Log2File=", 9) == 0) {
				this->Log2File = atoi(buf + 9);
				continue;
			}

			if (_strnicmp(buf, "StayOnTop=", 10) == 0) {
				this->StayOnTop = atoi(buf + 10);
				continue;
			}
			
			if (_strnicmp(buf, "Log2csv=", 8) == 0) {
				this->Log2csv = atoi(buf + 8);
				continue;
			}

			if (_strnicmp(buf, "ShowAll=", 8) == 0) {
				this->ShowAll = atoi(buf + 8);
				continue;
			}
			
			if (_strnicmp(buf, "ShowTempIcon=", 13) == 0) {
				this->ShowTempIcon = atoi(buf + 13);
				continue;
			}

			if (_strnicmp(buf, "SensorName1=", 12) == 0) {
				strncpy_s(this->gSensorNames[0], sizeof(this->gSensorNames[0]), buf + 12, 3);
				continue;
			}

			if (_strnicmp(buf, "SensorName2=", 12) == 0) {
				strncpy_s(this->gSensorNames[1], sizeof(this->gSensorNames[1]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName3=", 12) == 0) {
				strncpy_s(this->gSensorNames[2], sizeof(this->gSensorNames[2]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName4=", 12) == 0) {
				strncpy_s(this->gSensorNames[3], sizeof(this->gSensorNames[3]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName5=", 12) == 0) {
				strncpy_s(this->gSensorNames[4], sizeof(this->gSensorNames[4]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName6=", 12) == 0) {
				strncpy_s(this->gSensorNames[5], sizeof(this->gSensorNames[5]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName7=", 12) == 0) {
				strncpy_s(this->gSensorNames[6], sizeof(this->gSensorNames[6]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName8=", 12) == 0) {
				strncpy_s(this->gSensorNames[7], sizeof(this->gSensorNames[7]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName9=", 12) == 0) {
				strncpy_s(this->gSensorNames[8], sizeof(this->gSensorNames[8]), buf + 12, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName10=", 13) == 0) {
				strncpy_s(this->gSensorNames[9], sizeof(this->gSensorNames[9]), buf + 13, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName11=", 13) == 0) {
				strncpy_s(this->gSensorNames[10], sizeof(this->gSensorNames[10]), buf + 13, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName12=", 13) == 0) {
				strncpy_s(this->gSensorNames[11], sizeof(this->gSensorNames[11]), buf + 13, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName13=", 13) == 0) {
				strncpy_s(this->gSensorNames[12], sizeof(this->gSensorNames[12]), buf + 13, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName14=", 13) == 0) {
				strncpy_s(this->gSensorNames[13], sizeof(this->gSensorNames[13]), buf + 13, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName15=", 13) == 0) {
				strncpy_s(this->gSensorNames[14], sizeof(this->gSensorNames[14]), buf + 13, 3);
				continue;
			}
			
			if (_strnicmp(buf, "SensorName16=", 13) == 0) {
				strncpy_s(this->gSensorNames[15], sizeof(this->gSensorNames[15]), buf + 13, 3);
				continue;
			}

			if (_strnicmp(buf, "SensorOffset1=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[0].offs, &this->SensorOffset[0].hystMin, &this->SensorOffset[0].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset2=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[1].offs, &this->SensorOffset[1].hystMin, &this->SensorOffset[1].hystMax);
				continue;
			}

			if (_strnicmp(buf, "SensorOffset3=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[2].offs, &this->SensorOffset[2].hystMin, &this->SensorOffset[2].hystMax);
				continue;
			}

			if (_strnicmp(buf, "SensorOffset4=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[3].offs, &this->SensorOffset[3].hystMin, &this->SensorOffset[3].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset5=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[4].offs, &this->SensorOffset[4].hystMin, &this->SensorOffset[4].hystMax);
				continue;
			}

			if (_strnicmp(buf, "SensorOffset6=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[5].offs, &this->SensorOffset[5].hystMin, &this->SensorOffset[5].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset7=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[6].offs, &this->SensorOffset[6].hystMin, &this->SensorOffset[6].hystMax);
				continue;
			}

			if (_strnicmp(buf, "SensorOffset8=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[7].offs, &this->SensorOffset[7].hystMin, &this->SensorOffset[7].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset9=", 14) == 0) {
				sscanf_s(buf + 14, "%d %d %d", &this->SensorOffset[8].offs, &this->SensorOffset[8].hystMin, &this->SensorOffset[8].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset10=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[9].offs, &this->SensorOffset[9].hystMin, &this->SensorOffset[9].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset11=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[10].offs, &this->SensorOffset[10].hystMin, &this->SensorOffset[10].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset12=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[11].offs, &this->SensorOffset[11].hystMin, &this->SensorOffset[11].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset13=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[12].offs, &this->SensorOffset[12].hystMin, &this->SensorOffset[12].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset14=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[13].offs, &this->SensorOffset[13].hystMin, &this->SensorOffset[13].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset15=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[14].offs, &this->SensorOffset[14].hystMin, &this->SensorOffset[14].hystMax);
				continue;
			}
			
			if (_strnicmp(buf, "SensorOffset16=", 15) == 0) {
				sscanf_s(buf + 15, "%d %d %d", &this->SensorOffset[15].offs, &this->SensorOffset[15].hystMin, &this->SensorOffset[15].hystMax);
				continue;
			}

			if (_strnicmp(buf, "IgnoreSensors=", 14) == 0) {
				char* p = buf + 14, * p2 = this->IgnoreSensors;
				while (*p) {	// copy excluding space and tab
					if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
						*p2++ = *p;
					p++;
				}
				*p2 = '\0';
				continue;
			}
		}

		fclose(f);

		if (this->StayOnTop)
			this->hwndDialog = ::CreateDialogParam(hinstapp,
				MAKEINTRESOURCE(9000),
				HWND_DESKTOP,
				(DLGPROC)BaseDlgProc,
				(LPARAM)this);

		else
			this->hwndDialog = ::CreateDialogParam(hinstapp,
				MAKEINTRESOURCE(9002),
				HWND_DESKTOP,
				(DLGPROC)BaseDlgProc,
				(LPARAM)this);

		// end marker for smart levels array
		if (lcnt1) {
			this->SmartLevels[lcnt1].temp = -1;
			this->SmartLevels1[lcnt1].temp1 = -1;
			this->SmartLevels[lcnt1].fan = 0x80;
			this->SmartLevels1[lcnt1].fan1 = 0x80;
		}

		if (lcnt2) {
			this->SmartLevels2[lcnt2].temp2 = -1;
			this->SmartLevels2[lcnt2].fan2 = 0x80;
		}

		ok = true;

		this->Trace("Current Config:");
		this->Trace(FANCONTROLVERSION);
	}
	else {
		this->Trace("TPFanControl.ini missing, default values:");
	}

	HANDLE hLockS = CreateMutex(NULL, FALSE, "TPFanControlMutex01");

	if (hLockS == NULL) Runs_as_service = true;
	if (WAIT_OBJECT_0 != WaitForSingleObject(hLockS, 0))
		Runs_as_service = true;

	//Offset Fahrenheit to Celsius
	if (this->SmartLevels[0].temp >= 80) Fahrenheit = true;

	// Set ProcessPriority
	bool _SPC;
	switch (ProcessPriority) {
	case 5: _SPC = SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS); break;
	case 4: _SPC = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS); break;
	case 3: _SPC = SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS); break;
//  case 2: _SPC = SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS); break;
	case 1: _SPC = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS); break;
	case 0: _SPC = SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS); break;
	default: break; // _SPC = SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS); 
	}

	//
	// display config
	//
	if (this->IconCycle <= 0 || this->IconCycle >= 60) this->IconCycle = 1;
	sprintf_s(buf, sizeof(buf), "  Active= %d, Cycle= %d, FanBeep= %d %d, MaxReadErrors= %d",
		this->ActiveMode, this->Cycle,
		this->FanBeepFreq, this->FanBeepDura, this->MaxReadErrors);
	this->Trace(buf);

	sprintf_s(buf, sizeof(buf), "  IconLevels= %d %d %d, NoExtSensor= %d, Lev64Norm= %d",
		this->IconLevels[0], this->IconLevels[1], this->IconLevels[2],
		this->NoExtSensor, this->Lev64Norm);
	this->Trace(buf);

	sprintf_s(buf, sizeof(buf), "  Log2File= %d, Log2csv= %d, ShowAll= %d, IconColorFan= %d",
		this->Log2File, this->Log2csv, this->ShowAll, this->IconColorFan);
	this->Trace(buf);

	this->ShowAllToDialog(ShowAll);

	setzero(buf, sizeof(buf));

	if (Fahrenheit) {
		strcpy_s(buf, sizeof(buf), "  ");
		for (i = 0; this->SmartLevels[i].temp != -1; i++) {
			sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%d° F->", i > 0 ? ", " : "", this->SmartLevels[i].temp);
			if (this->SmartLevels[i].fan != 0x80)
				sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%d", this->SmartLevels[i].fan);
			else
				strcat_s(buf, sizeof(buf), "0x80");
		}
	}
	else {
		strcpy_s(buf, sizeof(buf), "  Levels= ");
		for (i = 0; this->SmartLevels[i].temp != -1; i++) {
			sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%d° C -> ", i > 0 ? ",  " : "", this->SmartLevels[i].temp);
			if (this->SmartLevels[i].fan != 0x80)
				sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%d", this->SmartLevels[i].fan);
			else
				strcat_s(buf, sizeof(buf), "0x80");
		}
	}
	this->Trace(buf);

	//Levels2	

	if (this->SmartLevels2[0].temp2 != 0)
	{
		if (Fahrenheit) {
			strcpy_s(buf, sizeof(buf), "  ");
			for (i = 0; this->SmartLevels2[i].temp2 != -1; i++) {
				sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%d° F->", i > 0 ? ", " : "", this->SmartLevels2[i].temp2);
				if (this->SmartLevels2[i].fan2 != 0x80)
					sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%d", this->SmartLevels2[i].fan2);
				else
					strcat_s(buf, sizeof(buf), "0x80");
			}
		}
		else {
			strcpy_s(buf, sizeof(buf), "  Levels2= ");
			for (i = 0; this->SmartLevels2[i].temp2 != -1; i++) {
				sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%d° C -> ", i > 0 ? ",  " : "", this->SmartLevels2[i].temp2);
				if (this->SmartLevels2[i].fan2 != 0x80)
					sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%d", this->SmartLevels2[i].fan2);
				else
					strcat_s(buf, sizeof(buf), "0x80");
			}
		}
		this->Trace(buf);
	}

	if (Fahrenheit) {
		sprintf_s(buf, sizeof(buf), "  SensorOffset1-12= %d %d %d %d %d %d %d %d %d %d %d %d ° F",
			this->SensorOffset[0].offs, this->SensorOffset[1].offs, this->SensorOffset[2].offs,
			this->SensorOffset[3].offs, this->SensorOffset[4].offs, this->SensorOffset[5].offs,
			this->SensorOffset[6].offs, this->SensorOffset[7].offs, this->SensorOffset[8].offs,
			this->SensorOffset[9].offs, this->SensorOffset[10].offs, this->SensorOffset[11].offs);

		for (i = 0; i < 15; i++) { SensorOffset[i].offs = SensorOffset[i].offs * 5 / 9; }
	}
	else {
		sprintf_s(buf, sizeof(buf), "  SensorOffset1-12= %d %d %d %d %d %d %d %d %d %d %d %d ° C",
			this->SensorOffset[0].offs, this->SensorOffset[1].offs, this->SensorOffset[2].offs,
			this->SensorOffset[3].offs, this->SensorOffset[4].offs, this->SensorOffset[5].offs,
			this->SensorOffset[6].offs, this->SensorOffset[7].offs, this->SensorOffset[8].offs,
			this->SensorOffset[9].offs, this->SensorOffset[10].offs, this->SensorOffset[11].offs);
	}
	this->Trace(buf);

	sprintf_s(buf, sizeof(buf), "  IgnoreSensors= %s, ProcessPriority= %d, IconCycle= %d", IgnoreSensors, ProcessPriority, IconCycle);
	this->Trace(buf);

	sprintf_s(buf, sizeof(buf), "  BluetoothEDR= %d, NoWaitMessage= %d, ShowBiasedTemps= %d", this->BluetoothEDR, NoWaitMessage, ShowBiasedTemps);
	this->Trace(buf);

	//ManModeExit Fahrenheit to Celsius and v.v.

	if (Fahrenheit && (this->ManModeExit == 80))
		this->ManModeExit = (this->ManModeExit * 9 / 5) + 32;

	if (Fahrenheit)
		this->ManModeExitInternal = (this->ManModeExit - 32) * 5 / 9;
	else
		this->ManModeExitInternal = this->ManModeExit;

	sprintf_s(buf, sizeof(buf), "  ManModeExit= %d, SecWinUptime= %d, SecStartDelay= %d", this->ManModeExit, this->SecWinUptime, this->SecStartDelay);
	this->Trace(buf);

	//Offset& Smartlevels Fahrenheit to Celsius
	if (Fahrenheit) {
		for (i = 0; this->SmartLevels[i].temp != -1; i++) { this->SmartLevels[i].temp = (this->SmartLevels[i].temp - 32) * 5 / 9; }
		for (i = 0; this->SmartLevels1[i].temp1 != -1; i++) { this->SmartLevels1[i].temp1 = (this->SmartLevels1[i].temp1 - 32) * 5 / 9; }
		if (this->SmartLevels2[0].temp2 == 0); // Indikator für 2.Profil
		else this->SmartLevels2[0].temp2 = (this->SmartLevels2[0].temp2 - 32) * 5 / 9;
		for (i = 1; this->SmartLevels2[i].temp2 != -1; i++) { this->SmartLevels2[i].temp2 = (this->SmartLevels2[i].temp2 - 32) * 5 / 9; }
		//		for (i= 0; i<15; i++) {SensorOffset[i]= SensorOffset[i] * 5/9;}
		this->IconLevels[0] = (this->IconLevels[0] - 32) * 5 / 9;
		this->IconLevels[1] = (this->IconLevels[1] - 32) * 5 / 9;
		this->IconLevels[2] = (this->IconLevels[2] - 32) * 5 / 9;
	}

	this->Trace("");

	if (this->Log2csv == 1) {
		int	delfile = system("del TPFanControl_last_csv.txt && ren TPFanControl_csv.txt TPFanControl_last_csv.txt");

		sprintf_s(buf, sizeof(buf), "time;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;rpm;fan;switch;", 
			this->gSensorNames[0], this->gSensorNames[1], this->gSensorNames[2], 
			this->gSensorNames[3], this->gSensorNames[4], this->gSensorNames[5],
			this->gSensorNames[6], this->gSensorNames[7], this->gSensorNames[8],
			this->gSensorNames[9], this->gSensorNames[10], this->gSensorNames[11]);
		this->Tracecsvod(buf);
	}

	// initial values
	this->TaskbarNew = 0;
	this->MaxTemp = 0;
	this->iMaxTemp = 0;
	this->iFarbeIconB = 10;
	this->iFontIconB = 9;
	this->lastfan1speed = 0;
	this->lastfan2speed = 0;
	this->fan1speed = 0;

	return ok;
}

//-------------------------------------------------------------------------
//  localized date&time
//-------------------------------------------------------------------------
void
FANCONTROL::CurrentDateTimeLocalized(char* result, size_t sizeof_result) {
	SYSTEMTIME s;
	::GetLocalTime(&s);

	char otfmt[64] = "HH:mm:ss", otime[64];
	char odfmt[128], odate[64];

	::GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_STIMEFORMAT, otfmt, sizeof(otfmt));

	::GetTimeFormat(LOCALE_USER_DEFAULT, 0, &s, otfmt, otime, sizeof(otime));

	::GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SSHORTDATE, odfmt, sizeof(odfmt));

	::GetDateFormat(LOCALE_USER_DEFAULT, 0, &s, odfmt, odate, sizeof(odate));

	setzero(result, sizeof_result);
	strncpy_s(result, sizeof_result, odate, sizeof_result - 2);
	strcat_s(result, sizeof_result, " ");
	strncat_s(result, sizeof_result, otime, sizeof_result - strlen(result) - 1);
}

//-------------------------------------------------------------------------
//  localized time
//-------------------------------------------------------------------------
void
FANCONTROL::CurrentTimeLocalized(char* result, size_t sizeof_result) {
	SYSTEMTIME s;
	::GetLocalTime(&s);

	char otfmt[64] = "HH:mm:ss", otime[64];

	::GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_STIMEFORMAT, otfmt, sizeof(otfmt));

	::GetTimeFormat(LOCALE_USER_DEFAULT, 0, &s, otfmt, otime, sizeof(otime));

	setzero(result, sizeof_result);
	strncat_s(result, sizeof_result, otime, sizeof_result - 1);
}

//-------------------------------------------------------------------------
//  
//-------------------------------------------------------------------------
bool
FANCONTROL::IsMinimized(void) const {
	WINDOWPLACEMENT wp = NULLSTRUCT;

	::GetWindowPlacement(this->hwndDialog, &wp);

	return wp.showCmd == SW_SHOWMINIMIZED;
}

//-------------------------------------------------------------------------
//  show trace output in lower window part
//-------------------------------------------------------------------------
void
FANCONTROL::Trace(const char* text) {
	char trace[16384] = "", datebuf[128] = "", line[512] = "";

	this->CurrentDateTimeLocalized(datebuf, sizeof(datebuf));

	if (strlen(text))
		sprintf_s(line, sizeof(line), "[%s] %s\r\n", datebuf, text);
	else
		strcpy_s(line, sizeof(line), "\r\n");

	::GetDlgItemText(this->hwndDialog, 9200, trace, sizeof(trace) - strlen(line) - 1);

	strcat_s(trace, sizeof(trace), line);

	// display 100 lines max
	char* p = trace + strlen(trace);
	int linecount = 0;

	while (p >= trace) {
		if (*p == '\n') {
			linecount++;
			if (linecount > 100)
				break;
		}
		p--;
	}

	// write logfile
	if (this->Log2File == 1) {
		FILE* flog;
		errno_t errflog = fopen_s(&flog, "TPFanControl.log", "ab");
		if (!errflog) {
			fwrite(line, strlen(line), 1, flog);
			fclose(flog);
		}
	}

	// redisplay log and scroll to bottom
	::SetDlgItemText(this->hwndDialog, 9200, p + 1);
	::SendDlgItemMessage(this->hwndDialog, 9200, EM_SETSEL, strlen(trace) - 2, strlen(trace) - 2);
	::SendDlgItemMessage(this->hwndDialog, 9200, EM_LINESCROLL, 0, 9999);
}

void
FANCONTROL::Tracecsv(const char* text) {
	char datebuf[128] = "", line[512] = "";

	this->CurrentTimeLocalized(datebuf, sizeof(datebuf));

	if (strlen(text))
		sprintf_s(line, sizeof(line), "%s; %s\r\n", datebuf, text);
	else
		strcpy_s(line, sizeof(line), "\r\n");

	// write logfile
	if (this->Log2csv == 1) {
		FILE* flogcsv;
		errno_t errflogcsv = fopen_s(&flogcsv, "TPFanControl_csv.txt", "ab");
		if (!errflogcsv) { 
			fwrite(line, strlen_s(line, sizeof(line)), 1, flogcsv); 
			fclose(flogcsv); 
		}
	}
}

void
FANCONTROL::Tracecsvod(const char* text) {
	char datebuf[128] = "", line[512] = "";

	this->CurrentDateTimeLocalized(datebuf, sizeof(datebuf));

	if (strlen(text))
		sprintf_s(line, sizeof(line), "%s\r\n", text);
	else
		strcpy_s(line, sizeof(line), "\r\n");

	// write logfile
	if (this->Log2csv == 1) {
		FILE* flogcsv;
		errno_t errflogcsv = fopen_s(&flogcsv, "TPFanControl_csv.txt", "ab");
		if (!errflogcsv) { 
			fwrite(line, strlen(line), 1, flogcsv); 
			fclose(flogcsv); 
		}
	}
}

//-------------------------------------------------------------------------
//  create a thread
//-------------------------------------------------------------------------
HANDLE
FANCONTROL::CreateThread(int(_stdcall* fnct)(ULONG), ULONG p) {
	LPTHREAD_START_ROUTINE thread = (LPTHREAD_START_ROUTINE)fnct;
	DWORD tid;
	HANDLE hThread;
	hThread = ::CreateThread(NULL, 8 * 4096, thread, (void*)p, 0, &tid);
	return hThread;
}
