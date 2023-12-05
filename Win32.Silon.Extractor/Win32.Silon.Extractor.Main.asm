.686
.model flat,stdcall
option casemap:none

include Win32.Silon.Extractor.Vars.inc
include Win32.Silon.Extractor.Funcs.asm

.code

GUI_DlgProc PROC hWnd:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM 
	.if uMsg == WM_INITDIALOG
		push hWnd
		pop hWindow
		invoke LoadIcon,hInstance,ICON
		invoke SendMessage,hWindow,WM_SETICON,1,eax
		invoke GetDlgItem,hWindow,IDC_NAME
		invoke SetFocus,eax 
		invoke MessageBox,hWindow,CTXT("Run within a virtual environment only when extracting keys",21h,0dh,0ah,"Not quite done with that bit yet :o",29h),CTXT("-=[ Infection warning"),MB_ICONEXCLAMATION
	.elseif uMsg == WM_COMMAND
		mov	eax,wParam
		.if eax == IDC_SMOPEN
			invoke GUI_OpenSelectedFile,ADDR szModulePath,ADDR szModuleFilter,IDC_FILEPATH
			.if eax != 0
				invoke GetDlgItem,hWindow,IDC_EXTRACT
				invoke EnableWindow,eax,1
			.endif
		.elseif eax == IDC_EXTRACT
			; Clear the ListBox before we begin
			invoke GetDlgItem,hWindow,IDC_LISTBOX
			invoke SendMessage,eax,LB_RESETCONTENT,NULL,NULL
			
			push OFFSET szModulePath
			call LoadMalicousModule
			
			; Can't unload the damn module so I will disable the 'Extract' button until I figure this out
			invoke GetDlgItem,hWindow,IDC_EXTRACT
			invoke EnableWindow,eax,0
		.elseif eax==IDC_ABOUT
			invoke MessageBox,hWindow,CTXT("Win32.Silon RC4 key extraction utility.",0dh,0ah,"Version: 0.2.2.3"),CTXT("-=[ CSIS Security Group"),MB_ICONINFORMATION
		.elseif eax==IDC_EXIT
			invoke SendMessage,hWindow,WM_CLOSE,0,0
		.endif
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWindow,0
	.endif
	
	@return:
	xor eax,eax
	ret 
GUI_DlgProc ENDP 

GUI_OpenSelectedFile PROC path:DWORD,filter:DWORD,field:DWORD
	mov ofn.lStructSize,SIZEOF ofn
	push hWindow
	pop  ofn.hwndOwner
	push hInstance
	pop  ofn.hInstance
	mov eax,filter
	mov  ofn.lpstrFilter,eax
	mov eax,path
	mov  ofn.lpstrFile,eax
	mov  ofn.nMaxFile,MAX_PATH
	mov  ofn.Flags, OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_LONGNAMES or OFN_EXPLORER or OFN_HIDEREADONLY
	mov  ofn.lpstrTitle, OFFSET szOurTitle
	
	push OFFSET ofn
	call GetOpenFileName
	
	test eax,eax
	jz @good
		push path
		push field
		push hWindow
		call SetDlgItemText
		ret
	@good:

	push OFFSET szFilePathError
	push IDC_FILEPATH
	push hWindow
	call SetDlgItemText
	
	xor eax,eax
	ret
GUI_OpenSelectedFile ENDP

GUI_AddListboxItem PROC key:DWORD
	invoke GetDlgItem,hWindow,IDC_LISTBOX
	invoke SendMessage,eax,LB_ADDSTRING,0,key
	
	ret    
GUI_AddListboxItem ENDP

start:

invoke GetModuleHandle, NULL 
mov hInstance,eax
invoke GetCommandLine
mov hCmdLine,eax
invoke DialogBoxParam,hInstance,IDD_LOADER,0,ADDR GUI_DlgProc,0 
invoke ExitProcess,eax 


Main PROC
	; Ensure that we got a valid path to work with
	cmp eax,0
	jz @PathError
		; Load the module with the module and path as arguments
		push eax
		push OFFSET szModulePath
		call LoadMalicousModule
		
		cmp eax,1
		jle @LoadError
			jmp @Return

	@LoadError:
	invoke MessageBox,hWindow,CTXT("There was an error loading the Silon module"),CTXT("Load Error"),MB_ICONERROR
	jmp @Return
	
	@PathError:
	invoke MessageBox,hWindow,CTXT("There was an error when resolving the Silon module's path"),CTXT("Path Error"),MB_ICONERROR
	
	@Return:
	ret
Main ENDP

end start