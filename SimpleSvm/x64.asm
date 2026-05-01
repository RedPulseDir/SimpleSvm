;
; @file       x64.asm
; @brief      Full assembly code for SVM hypervisor
;

.data

EXTERN OriginalLstar: QWORD
EXTERN SyscallHandler: QWORD
EXTERN TargetDR3: QWORD

.code

; ============================================================================
; PUSHAQ/POPAQ macros
; ============================================================================

PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      ; Dummy for rsp
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx    ; Dummy for rsp
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

SAVE_XMM macro
        movaps  xmmword ptr [rsp + 00h], xmm0
        movaps  xmmword ptr [rsp + 10h], xmm1
        movaps  xmmword ptr [rsp + 20h], xmm2
        movaps  xmmword ptr [rsp + 30h], xmm3
        movaps  xmmword ptr [rsp + 40h], xmm4
        movaps  xmmword ptr [rsp + 50h], xmm5
        endm

RESTORE_XMM macro
        movaps  xmm5, xmmword ptr [rsp + 50h]
        movaps  xmm4, xmmword ptr [rsp + 40h]
        movaps  xmm3, xmmword ptr [rsp + 30h]
        movaps  xmm2, xmmword ptr [rsp + 20h]
        movaps  xmm1, xmmword ptr [rsp + 10h]
        movaps  xmm0, xmmword ptr [rsp + 00h]
        endm

; ============================================================================
; Constants
; ============================================================================

KTRAP_FRAME_SIZE        equ     190h
MACHINE_FRAME_SIZE      equ     28h
XMM_SAVE_SIZE           equ     80h

; ============================================================================
; LaunchVm - Enter VM loop
; ============================================================================
; Parameters:
;   RCX = GuestVmcbPa (pointer to VMCB)
; ============================================================================

LaunchVm PROC FRAME
        mov     rsp, rcx                ; Switch to host stack

Lvm10:  mov     rax, [rsp]              ; RAX = GuestVmcbPa
        vmload  rax                     ; Load guest state
        vmrun   rax                     ; Enter guest mode
        vmsave  rax                     ; Save guest state after VMEXIT
        
        ; Allocate trap frame for debugging
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE
        
        ; Save guest GPRs
        PUSHAQ
        
        ; Setup parameters for SvHandleVmExit
        ; RCX = VpData, RDX = GuestRegisters
        mov     rdx, rsp                ; RDX = GuestRegisters
        mov     rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]  ; RCX = VpData
        
        ; Save XMM registers
        sub     rsp, XMM_SAVE_SIZE
        SAVE_XMM
        .endprolog
        
        call    SvHandleVmExit          ; Handle VMEXIT
        
        ; Restore XMM registers
        RESTORE_XMM
        add     rsp, XMM_SAVE_SIZE
        
        ; Restore guest GPRs
        test    al, al
        POPAQ
        
        jnz     Lvm20                   ; Exit if requested
        add     rsp, KTRAP_FRAME_SIZE   ; Otherwise continue
        jmp     Lvm10

Lvm20:  ; Exit virtualization
        ; RBX = Return address
        ; RCX = Original stack pointer
        ; EDX:EAX = VpData address
        mov     rsp, rcx
        mov     ecx, 'SSVM'             ; Magic value
        jmp     rbx
        
LaunchVm ENDP

; ============================================================================
; SyscallHook - LSTAR hook for syscall interception
; ============================================================================

SyscallHook PROC FRAME
        ; Check DR3 magic for interception
        mov     rax, dr3
        cmp     rax, qword ptr [TargetDR3]
        jne     go_original
        
        ; Check DR7 for global/local breakpoint
        mov     rax, dr7
        and     rax, 0F0000040h
        cmp     rax, 40h
        jne     go_original
        
        ; Check if syscall handler is set
        cmp     qword ptr [SyscallHandler], 0
        je      go_original
        
        ; Save volatile registers
        sub     rsp, 40h
        mov     [rsp], rcx
        mov     [rsp+8], rdx
        mov     [rsp+10h], r8
        mov     [rsp+18h], r9
        mov     [rsp+20h], r10
        mov     [rsp+28h], r11
        
        ; Call target handler
        mov     rcx, r10               ; First parameter
        mov     rdx, r11               ; Second parameter
        call    qword ptr [SyscallHandler]
        
        ; Restore registers
        mov     r11, [rsp+28h]
        mov     r10, [rsp+20h]
        mov     r9,  [rsp+18h]
        mov     r8,  [rsp+10h]
        mov     rdx, [rsp+8]
        mov     rcx, [rsp]
        add     rsp, 40h
        
        ; Return via sysret
        sysretq

go_original:
        jmp     qword ptr [OriginalLstar]
        
SyscallHook ENDP

; ============================================================================
; InvalidatePage - Invalidate TLB entry
; ============================================================================

InvalidatePage PROC
        invlpg  [rcx]
        ret
InvalidatePage ENDP

END
