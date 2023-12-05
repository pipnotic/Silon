include windows.inc 
include kernel32.inc
include user32.inc
include comdlg32.inc

include C:\masm32\macros\macros.asm

includelib	kernel32.lib
includelib user32.lib
includelib comdlg32.lib

; Prototypes
GUI_DlgProc				PROTO		:DWORD,:DWORD,:DWORD,:DWORD
LoadMalicousModule		PROTO		:DWORD
GUI_AddListboxItem		PROTO		:DWORD
GUI_OpenSelectedFile		PROTO		:DWORD,:DWORD,:DWORD

.const
IDD_LOADER		EQU 			1001
IDC_NAME 		EQU 			1002
IDC_EXIT 		EQU 			1006
IDC_FILEPATH 	EQU 			1009
IDC_SMOPEN 		EQU 			1011
IDC_EXTRACT		EQU				1022
IDC_ABOUT		EQU				1023
ICON 			EQU 			2000
IDC_LISTBOX		EQU				1035


; Uninitialised data
.data?
hInstance		HINSTANCE 			?
hWindow		HWND				?
hCmdLine	DWORD				?
hModBase	DWORD				?
hModSize		DWORD				?
hFuncCall	DWORD				?


; Initialised data
.data
ofn				OPENFILENAME	<SIZEOF OPENFILENAME>
lpOverLapped		OVERLAPPED		<SIZEOF OVERLAPPED>

szOurTitle			BYTE 			"File Selection",0
szOutputFile		BYTE			"Your-keys-sir.txt",0
szModuleFilter		BYTE 			"Executable Files",0,"*.*",0,0
szFilePathError	BYTE			"Error when selecting file. Please try again.",0

szModulePath		BYTE			MAX_PATH DUP(0)
szModule			BYTE			128 DUP(0)
hFormat			BYTE			32 DUP(0)

RC4sig			BYTE			55h,8Bh,0ECh,81h,0ECh,1Ch,01h,00h,00h,56h,8Dh,85h,0F0h,0FEh
