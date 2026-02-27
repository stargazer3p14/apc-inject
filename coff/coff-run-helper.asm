PUBLIC	imp_plug
PUBLIC	imp_plug_size
PUBLIC	imp_plug_addr_offs

.code

imp_plug_size	DD	_IMP_PLUG_SIZE
imp_plug_addr_offs	DD	_IMP_ADDR_OFFS

imp_plug:
	; Some register not preserved across function call
;	mov	r14, 1234567812345678h			; Need some long number so that MASM won't use shorted instruction version
	mov	rax, 1234567812345678h			; Need some long number so that MASM won't use shorted instruction version
_IMP_ADDR_OFFS 	EQU $ - imp_plug - 8
;	call	r14
	call	rax
	ret
_IMP_PLUG_SIZE EQU $ - imp_plug

END