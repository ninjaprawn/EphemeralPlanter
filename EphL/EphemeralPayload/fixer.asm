.CODE
ALIGN 16

asm_func PROC
MOV EAX, 1h
ADD RSP, 70h
POP RSI
POP RBP
POP RBX
RET
asm_func ENDP

END