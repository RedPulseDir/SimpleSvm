;
; @file       x64.asm
; @brief      Assembly code for SVM hypervisor
; @author     Fox (based on Satoshi Tanda)
;

.data

EXTERN g_OriginalLstar: QWORD
EXTERN g_TargetSysHandler: QWORD

.const

KTRAP_FRAME_SIZE        equ     190h
MACHINE_FRAME_SIZE      equ     28h
XMM_SAVE_SIZE           equ     80h

.code

; ============================================================================
; MACROS
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
; LaunchVm - Enter VM loop
; ============================================================================
; Parameters:
;   RCX = GuestVmcbPa (pointer to VMCB)
; ============================================================================

LaunchVm proc frame
        mov     rsp, rcx                ; Switch to host stack
        
        ; Stack layout after switch:
        ; Rsp+0x00: GuestVmcbPa
        ; Rsp+0x08: HostVmcbPa
        ; Rsp+0x10: Self
        ; Rsp+0x18: SharedVpData
        ; Rsp+0x20: Padding
        ; Rsp+0x28: Magic (MAXUINT64)

Lvm10:  mov     rax, [rsp]              ; RAX = GuestVmcbPa
        vmload  rax                     ; Load guest state
        
        vmrun   rax                     ; Enter guest mode
        
        vmsave  rax                     ; Save guest state after VMEXIT
        
        ; Allocate trap frame for debugging
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h
        
        ; Save guest GPRs
        PUSHAQ
        
        ; Setup parameters for HandleVmExit
        ; RCX = VpData, RDX = GuestRegisters
        mov     rdx, rsp                ; RDX = GuestRegisters
        mov     rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]  ; RCX = VpData
        
        ; Save XMM registers
        sub     rsp, XMM_SAVE_SIZE
        SAVE_XMM
        .endprolog
        
        call    HandleVmExit            ; Handle VMEXIT
        
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
        
LaunchVm endp

; ============================================================================
; SystemCallHook - LSTAR hook for syscall interception
; ============================================================================

SystemCallHook proc frame
        
        ; Check DR3 magic for interception
        mov     rax, dr3
        cmp     rax, 0x7FFE0FF0h       ; TARGET_DR3
        jne     go_original
        
        mov     rax, dr7
        and     rax, 0F0000040h
        cmp     rax, 40h
        jne     go_original
        
        ; Check if target syscall handler is set
        cmp     qword ptr [g_TargetSysHandler], 0
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
        call    qword ptr [g_TargetSysHandler]
        
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
        jmp     qword ptr [g_OriginalLstar]
        
        .endprolog

SystemCallHook endp

; ============================================================================
; ReadDr - Read debug register safely
; ============================================================================

ReadDr proc
        mov     eax, ecx
        cmp     eax, 0
        je      read_dr0
        cmp     eax, 1
        je      read_dr1
        cmp     eax, 2
        je      read_dr2
        cmp     eax, 3
        je      read_dr3
        cmp     eax, 6
        je      read_dr6
        cmp     eax, 7
        je      read_dr7
        xor     rax, rax
        ret
        
read_dr0: mov   rax, dr0
        ret
read_dr1: mov   rax, dr1
        ret
read_dr2: mov   rax, dr2
        ret
read_dr3: mov   rax, dr3
        ret
read_dr6: mov   rax, dr6
        ret
read_dr7: mov   rax, dr7
        ret
ReadDr endp

; ============================================================================
; WriteDr - Write debug register safely
; ============================================================================

WriteDr proc
        mov     rax, rdx
        cmp     ecx, 0
        je      write_dr0
        cmp     ecx, 1
        je      write_dr1
        cmp     ecx, 2
        je      write_dr2
        cmp     ecx, 3
        je      write_dr3
        cmp     ecx, 6
        je      write_dr6
        cmp     ecx, 7
        je      write_dr7
        ret
        
write_dr0: mov   dr0, rax
        ret
write_dr1: mov   dr1, rax
        ret
write_dr2: mov   dr2, rax
        ret
write_dr3: mov   dr3, rax
        ret
write_dr6: mov   dr6, rax
        ret
write_dr7: mov   dr7, rax
        ret
WriteDr endp

; ============================================================================
; InvalidatePage - Invalidate TLB entry
; ============================================================================

InvalidatePage proc
        invlpg  [rcx]
        ret
InvalidatePage endp

end
