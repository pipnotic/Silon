.code

LoadMalicousModule PROC path:DWORD
	COMMENT &
	Arguments:
	- module: Base-address of the Silon module
	- path: Path to the module to load
	
	Return value:
	- 0: Path error
	- 1: LoadLibrary error 
	&
	
	; Make certain that we have a something to try and load
	cmp path,0
	jz @PathError
		mov esi,path
		
		; Load the module
		push path
		call LoadLibrary
		
		cmp eax,0
		jz @LoadLibError
			mov hModBase,eax
			
			; Try to find some calls to the RC4 function
			push eax
			call FindRC4FunctionCalls
			
			; Ensure that the module is unloaded after we are done with it
			; This shite doesn't work ATM, have to look into this. The library won't unload and you
			; can't force it
			push OFFSET hModBase
			call FreeLibrary
			call GetLastError
			
		@LoadLibError:
		; Move 1 to eax so that if we fail, we know it was due to the LoadLibrary call
		mov eax,1
		ret
		
	@PathError:
	; Clear eax so that if we fail, we know it is due to a path error
	xor eax,eax
	ret
LoadMalicousModule ENDP

GetModuleSize PROC USES edi esi ecx
	COMMENT &
	Arguments:
	- None
	
	Return value:
	-Success: Module size
	- Error: 0
	&
	LOCAL hFile:DWORD

	mov eax,hModBase
	; Zero counter
	xor edi,edi
	; Well use ESI as our access to the header(s)
	mov esi,eax
	; Point ESI at the IMAGE_NT_HEADERS structure
	add esi,DWORD PTR [esi+3Ch]
	; Get number of sections
	movzx ecx,WORD PTR [esi+6]
	; Sanity check
	test ecx,ecx
	; Jmp if no sections
	jz @NoSections
		; We want the last section, so sub one from the count
		sub ecx,1
		; Size of IMAGE_SECTION_HEADER structure
		mov eax,28h
		; Multiply by section count (-1)
		mul ecx
		; Use generated offset to point at last section header
		lea edi,DWORD PTR [esi+eax+0F8h]
		; Get IMAGE_SECTION_HEADER.Misc.VirtualSize
		mov eax,DWORD PTR [edi+8]
		; Add RVA of section
		add eax,DWORD PTR [edi+0ch]
		; Save copy to EDX'
		mov edx,eax
		; Strip anything above 0x1000h
		and edx,0FFFh
		; Any remainder?
		test edx,edx
		; Jump if no
		jz @Aligned
			; Strip anything below 0x1000h
			and eax, 0FFFFF000h
			; Align EAX to 0x1000h boundary
			add eax,1000h
		@Aligned:
		ret
		
	@NoSections:
	; No sections error
	xor eax,eax
	ret
GetModuleSize ENDP

FindRC4FunctionCalls PROC module:DWORD
	COMMENT &
	Arguments:
	- module: Base-address of the Silon module
	
	Return value:
	- Sucess: non-zero value
	- Error: 0FFFFFFFFh (-1)
	&
	mov esi,module
	
	call GetModuleSize
	mov hModSize,eax
	
	cmp eax,0
	jz @InvalidSize
		mov ecx,eax
		jmp @cond
		@loop:
			mov al,BYTE PTR [esi]
			cmp al,0e8h
			jnz @next
				; Save some values
				mov hFuncCall,esi
				push esi
				push ecx
				; Move past the call operation
				inc esi
				; Here we have to get the call target sorted
				; offset + call target = actual call target			
				mov eax,DWORD PTR [esi]
				add esi,eax
				add esi,4
				
				; Let us make sure the address is valid and readable so to avoid exceptions
				; The starting point of the Silon module has been stored in hSilonMod	
				mov eax,hModBase
				cmp esi,eax
				jbe @LowAddr
					add eax,hModSize
					cmp esi,eax
					jnb @HighAddr
						push esi
						call AddressPointsToRC4Func
						
						test eax,eax
						jz @InvalidAddr
							push hFuncCall
							call ExtractKeyData
						@InvalidAddr:
						
					@HighAddr:
					
				@LowAddr:
				pop ecx
				pop esi
	
			@next:
			inc esi
			dec ecx
			
			@cond:
			cmp ecx,0
		ja @loop
		jmp @Success
		
	@InvalidSize:
	mov eax,0FFFFFFFFh
	
	@Success:
	ret
FindRC4FunctionCalls endp

AddressPointsToRC4Func PROC USES ecx edi esi,address:DWORD
	COMMENT &
	Arguments:
	- address: Points to an address that MAY point to the RC4 function
	
	Return value:
	- Success: eax != 0
	- Error: eax = 0
	&
	
	mov esi,OFFSET RC4sig
	mov edi,address
	mov ecx,SIZEOF RC4sig
	
	jmp @cond
	@while:
		mov al,BYTE PTR [esi]
		mov ah,BYTE PTR[edi]
		; 0AAh is a wild card so move past it if it is there
		cmp al,0AAh
		jnz @f
			inc esi
			inc edi		
		@@:
		cmp al,ah
		jz @next
			; We found a mis-match, no need to continue
			; Clear eax and return
			xor eax,eax
			ret
		@next:
		inc edi
		inc esi
		dec ecx
		
		@cond:
		test ecx,ecx
	ja @while

	ret
AddressPointsToRC4Func endp

ExtractKeyData PROC location:DWORD
	COMMENT &
	Arguments:
	- location: Address located close to the call to the RC4 function
	
	Return value:
	- None.
	&
	
	LOCAL pKey:DWORD
	LOCAL pLen:DWORD
	
	pushad
	mov esi,location
	sub esi,16h
	mov ecx,16h
	jmp @cond
	@loop:
		mov al,BYTE PTR [esi]
		cmp al,6ah
		jnz @notlength
			inc esi
			movzx ebx,BYTE PTR [esi]
			mov pLen,ebx
		@notlength:
		
		cmp al,68h
		jnz @notkey
			inc esi
			mov ebx,DWORD PTR [esi]
			mov pKey,ebx
			jmp @found
		@notkey:
		
		inc esi
		dec ecx
		
		@cond:
		cmp ecx,0
	ja @loop
	
	@found:
	.if pKey != 0 && pLen != 0
		push pKey
		push pLen
		call ReadRC4Key
	.endif
	
	popad
	Ret
ExtractKeyData ENDP

ReadRC4Key PROC,keylen:DWORD,location:DWORD
	COMMENT &
	Arguments:
	- keylen: Length of the extracted key
	- location: Address at which the key can be read
	
	Return value:
	- Success: eax != 0
	- Error: eax = 0
	&
	
	LOCAL hMem:DWORD
	LOCAL pMem:DWORD

	invoke VirtualAlloc,NULL,keylen,MEM_COMMIT+MEM_RESERVE,PAGE_READWRITE
	cmp eax,0
	jz @Error
		mov hMem,eax
		invoke GlobalLock,hMem
		cmp eax,0
		jz @f
			mov pMem,eax
			mov edi,eax
			mov esi,location
			cld
			mov ecx,keylen
			rep movsb BYTE PTR[edi],BYTE PTR[esi]
			push eax
			push keylen
			call WriteRC4KeyData
			invoke GlobalUnlock,pMem
			
		@@:
		invoke VirtualFree,hMem,keylen,MEM_DECOMMIT+MEM_RELEASE
		
	@Error:
	xor eax,eax
	ret
ReadRC4Key ENDP

WriteRC4KeyData PROC,keylen:DWORD,buffer:DWORD
	COMMENT &
	Arguments:
	- keylen: Length of the extracted key
	- buffer: Address to allocated memory
	
	Return value:
	- None.
	&
	
	; Here we need to encode the hex bytes to ASCII so that we can display them
	; in the ListBox control
	push OFFSET hFormat
	push keylen
	push buffer
	call HexEncode
	
	; Now that the RC4 keys have been converted to ASCII, we can add the values
	; to the ListBox control
	push OFFSET hFormat
	call GUI_AddListboxItem	
	
	ret
WriteRC4KeyData ENDP

HexEncode PROC USES edi esi ebx pBuff:DWORD,dwLen:DWORD,pOutBuff:DWORD
	COMMENT &
	Arguments:
	- pBuff: Buffer containing bytes to be converted
	- dwLen: Number of bytes
	-pOutBuff: Address of output buffer
	
	Return value:
	- eax = address of pOutBuff
	&
	
	mov ebx,dwLen
	mov edi,pOutBuff
	test ebx,ebx
	mov esi,pBuff
	jz @f
		@loop:
			movzx eax,BYTE PTR [esi]
			mov ecx,eax
			add edi,2
			shr ecx,4
			and eax,1111b
			and ecx,1111b
			cmp eax,10
			sbb edx,edx
			adc eax,0
			lea eax,[eax+edx*8+37h]
			cmp ecx,10
			sbb edx,edx
			adc ecx,0
			shl eax,8
			lea ecx,[ecx+edx*8+37h]
			or eax,ecx
			inc esi
			mov [edi-2],ax
			dec ebx
			test ebx,ebx
		jnz @loop
	@@:
	
	mov eax,edi
	mov BYTE PTR [edi],0
	sub eax,pOutBuff
	ret
HexEncode ENDP