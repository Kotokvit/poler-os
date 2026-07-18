# POLER-OS — Контекстный промт для AI-ассистента

> Версия: 1.0 | Дата: 2026-07-19
> Ядро: v0.9.0 (Zig 0.13.0, x86_64, freestanding, ~25,500 LOC)
> Принцип: **«Программа — гость, а не хозяин»**

---

## 1. ЧТО ТАКОЕ POLER-OS

POLER-OS — 64-битная x86_64 ОС с **двойной натуральной личностью** (dual-personality kernel). Ядро реализует **два нативных API одновременно**: Windows NT (NtXxx syscalls 0x1000–0x1FFF) и POSIX/Linux (syscalls 0x0000–0x0FFF). Ни один из них не является эмуляцией, трансляцией или слоем совместимости — оба first-class.

**Уникальные архитектурные особенности:**

1. **Intent Layer** (5-фазная семантическая безопасность) — каждый I/O запрос инкапсулируется в Intent (72 байта) и проходит: PND v8 nonce → POLER Firewall (SipHash PRF + когнитивный цикл) → rate limiting → capability check → handle access_mask. Решает проблему Ambient Authority.

2. **POLER Firewall** — криптографический фаервол на основе PND v8 (параметрическая нелинейная диффузия, φ-обёртка `pndMix = φ(a·b) +% ε·φ(a⊕b)`, 20 раундов Фейстеля, AES MixColumns MDS) + SipHash PRF для обнаружения аномалий поведения.

3. **Capability Delegation Tree** — трёхуровневая модель безопасности: Capability Kernel (дерево делегирования, каскадное отзывание, max depth 8) → Policy Engine (whitelist-правила, Allow/Deny/Audit/RateLimit) → AI Capsule (restricted caps, memory quota, TTL, rollback snapshots).

4. **Object Manager** (Zircon-style) — унифицированное пространство имён для NT+POSIX, 13 типов объектов, per-process handle tables с access_mask (u32), `\??\C:\foo` и `/mnt/c/foo` ссылаются на один и тот же объект.

5. **AI Capsule Manager** — изолированные среды выполнения с ограниченными capabilities, квотами памяти, TTL и поддержкой снапшотов для отката.

6. **Dual-Personality Subsystem Dispatcher** — маршрутизация syscalls: POSIX (0x0000+), NT (0x1000+), POLER (0x2000+), AI (0x3000+). NTSTATUS ↔ errno конверсия. API Set resolver stub (891 виртуальных API Set из Win10).

7. **IOMMU (Intel VT-d)** — защита от DMA-атак: DMAR detection через ACPI, Root+Context+Second-Level Page Tables, identity-mapped трансляции.

---

## 2. АРХИТЕКТУРА ЯДРА

### 2.1. Поток загрузки

```
GRUB2 (Multiboot2) → boot64.S (32→64 transition, GDT64, paging, long mode)
  → _start() [main64.zig]:
    HAL init → PMM → VMM → Heap → Scheduler → ACPI → SMP → PCI
    → VirtIO-BLK → FAT32 → Object Manager → NT API → POSIX API
    → Capability → Policy Engine → IPC → AI Capsule → IOMMU → Intent Layer
    → Interactive Shell
```

### 2.2. Пайплайн безопасности (v0.9.0)

```
Userspace Syscall
    ↓
syscall_integration.zig (zig_syscall_handler)
    ↓
Intent Layer (poler/intent.zig) — 5 фаз:
    Phase 1:  PND v8 nonce verification (tamper detection)
    Phase 1b: POLER Firewall (SipHash PRF + cognitive cycle anomaly detection)
    Phase 2:  Rate limiting (token bucket per caller)
    Phase 3:  Process-level capability check (acl_capabilities bitmask)
    Phase 4:  Per-handle access_mask verification (Zircon Object Table)
    ↓
subsystem/subsystem.zig (dispatch)
    ├── POSIX (0x0000-0x0FFF)
    ├── NT     (0x1000-0x1FFF)
    ├── POLER  (0x2000-0x2FFF)
    └── AI     (0x3000-0x3FFF)
    ↓
kernel_integrate.zig → VFS → FAT32 / VirtIO-BLK
```

### 2.3. Структура Intent (72 байта)

```zig
pub const Intent = extern struct {
    category: IntentCategory,  // u8: FS/NET/PROC/MEM/HW/IPC/SYS
    action: IntentAction,      // u16: 40+ действий (FS_OPEN, PROC_CREATE, MEM_MMAP, etc.)
    caller_pid: u16,
    target_handle: u16,        // Object Manager handle
    args: [6]u64,              // 48 байт параметров
    nonce: u64,                // PND v8 nonce (tamper detection)
    _reserved: u32,            // padding → 72 total
};
```

### 2.4. Вердикт Intent

```zig
pub const IntentVerdict = enum(u8) {
    Allowed,
    Denied,
    RateLimited,
    InsufficientCapability,
    ObjectAccessDenied,
};
```

---

## 3. СТРУКТУРА КОДОВОЙ БАЗЫ

```
zig-kernel/
├── build.zig                    # Zig build (32-bit + 64-bit kernels, QEMU targets, ISO, tests)
├── build-iso.sh / build-iso-local.sh / build-minimal-iso.sh
├── run-qemu.sh / run-qemu-iso.sh
├── disk.img                     # FAT32 disk image для virtio-blk
│
├── docs/
│   ├── ROADMAP.md               # Дорожная карта проекта (v0.7.0)
│   ├── ROADMAP_AND_AUDIT.md     # Детальная дорожная карта + критический аудит
│   ├── POLER-OS-IMPLEMENTATION-PLAN.md  # План реализации (P0 fixes, VFS, network)
│   ├── CAPABILITY-DELEGATION-AUDIT-v1.0.md  # 12-секционный аудит (security score 7.5/10)
│   ├── LEGAL_AND_COMPAT_AUDIT.md         # Юридический анализ совместимости Windows API
│   ├── SMP_SPECIFICATION.md     # Спецификация SMP
│   └── SESSION_NOTES.md         # Контекст сессий
│
├── iso/boot/grub/grub.cfg       # GRUB конфигурация
│
├── src64/                       # ★ 64-битное ядро (основное)
│   ├── boot64.S                 # BSP boot: 32→64, GDT64, paging, long mode
│   ├── boot_smp.S               # AP trampoline: 16→32→64
│   ├── isr64.S                  # ISR stubs (256 векторов)
│   ├── linker64.ld              # Linker script (0x100000 identity-mapped)
│   │
│   ├── main64.zig               # ★ Точка входа (1470 строк)
│   ├── hal.zig                  # ★ HAL (~1800 строк): GDT, IDT, APIC, IO-APIC, keyboard, serial, SYSCALL/SYSRET
│   ├── scheduler.zig            # ★ Round-robin preemptive (430 строк): Ring 0/3, per-process CR3, TLS
│   ├── pmm64.zig                # Physical Memory Manager (bitmap + refcounting для COW)
│   ├── vmm64.zig                # Virtual Memory Manager (4-level paging, COW, SMP TLB)
│   ├── heap64.zig               # Kernel heap
│   ├── acpi.zig                 # ACPI (RSDP, RSDT, MADT)
│   ├── smp.zig                  # SMP (per-CPU data, AP init, SIPI)
│   ├── spinlock.zig             # Spinlock с PAUSE, tryAcquire, SpinlockGuard RAII
│   ├── framebuffer.zig          # VBE framebuffer (8x16 bitmap font, 32bpp)
│   ├── multiboot1.zig / multiboot2.zig  # Multiboot info parsers
│   ├── cpio.zig                 # CPIO initrd parser
│   ├── pci.zig                  # PCI bus enumeration (config space, BAR0, MMIO)
│   ├── virtio_blk.zig           # VirtIO-BLK driver (DMA read/write, virtqueue)
│   ├── fat32.zig                # FAT32 filesystem (read/write/create/delete, LFN)
│   ├── elf_loader.zig           # ★ ELF64 loader (3 версии: legacy, PML4, pure per-process)
│   ├── dynlinker.zig            # ★ Dynamic linker (ld-poler v1.0: .so, TLS, PLT, GOT, SHA-256 integrity)
│   ├── poler_core.zig           # ★ POLER Core v8 (PND hash, SipHash PRF, 20-round Feistel)
│   ├── rsa_oaep.zig             # RSA-OAEP (BigInt, SHA-256, MGF1, OAEP, CascadeCipher)
│   ├── capability.zig           # ★ Capability delegation tree, cascading revocation
│   ├── policy_engine.zig        # ★ Policy Engine (whitelist rules)
│   ├── ai_capsule.zig           # ★ AI Capsule Manager (lifecycle, restricted caps, rollback)
│   ├── ipc.zig                  # ★ Channel-based IPC (Zircon-inspired, handle transfer)
│   ├── iommu.zig                # ★ Intel VT-d IOMMU driver
│   ├── kernel_integrate.zig     # ★ VFS↔FAT32 (legacy), Process Mgr, ACL↔Auth, COW fork
│   ├── syscall_integration.zig  # ★ Syscall→Intent→Subsystem bridge
│   ├── vfs.zig                  # ★★ VFS Layer v1.0 — abstract filesystem (VfsOps vtable, mount table, unified path resolution)
│   │
│   ├── poler/
│   │   └── intent.zig           # ★★ Intent Layer — 5-phase semantic security dispatcher (~900 строк)
│   │
│   └── subsystem/
│       ├── subsystem.zig        # ★ Master dispatcher (NT/POSIX/POLER/AI routing)
│       ├── common/
│       │   └── object_manager.zig  # ★ Unified Object Manager (Zircon-style handles)
│       ├── nt/
│       │   └── nt_api.zig       # ★ Native NT API (NtXxx handlers, API Set resolver)
│       └── posix/
│           └── posix_api.zig    # ★ Native POSIX API (Linux syscall numbers)
```

---

## 4. ЗАВЕРШЁННЫЕ КОМПОНЕНТЫ (v0.9.0)

| Подсистема | Файлы | Статус |
|------------|-------|--------|
| Boot64 (32→64, GDT64, IDT, paging) | `boot64.S`, `isr64.S` | ✅ |
| HAL (GDT 9 entries, IDT 256 vectors, PIC→APIC→IO-APIC, TSS, SYSCALL/SYSRET) | `hal.zig` | ✅ |
| PMM (bitmap) + VMM (4-level paging, COW, per-process PML4) | `pmm64.zig`, `vmm64.zig` | ✅ |
| Kernel Heap | `heap64.zig` | ✅ |
| Scheduler (round-robin, preemptive, Ring 0/3, CR3 switch, TLS/FS_BASE) | `scheduler.zig` | ✅ |
| SMP (ACPI MADT, per-CPU data, AP trampoline, SIPI/IPI, spinlocks) | `acpi.zig`, `smp.zig`, `spinlock.zig` | ✅ |
| Framebuffer (1024×768×32bpp) + VGA text mode (80×25) | `framebuffer.zig` | ✅ |
| Keyboard (PS/2 scancode set 1) + Serial (COM1) | `hal.zig` | ✅ |
| PCI enumeration (config space, BAR0 I/O + MMIO) | `pci.zig` | ✅ |
| VirtIO-BLK driver (DMA, virtqueue, page-aligned buffers) | `virtio_blk.zig` | ✅ |
| FAT32 (read/write/create/delete, LFN, nested paths) | `fat32.zig` | ✅ |
| ELF64 Loader (3 versions, per-process PML4, dynamic linking) | `elf_loader.zig` | ✅ |
| Dynamic Linker (ld-poler v1.0: .so, PLT, GOT, TLS, SHA-256 integrity) | `dynlinker.zig` | ✅ |
| POLER Core v8 (PND hash, SipHash PRF, 20-round Feistel, φ-wrapper) | `poler_core.zig` | ✅ |
| RSA-OAEP (BigInt, SHA-256, MGF1, CascadeCipher) | `rsa_oaep.zig` | ✅ |
| Capability System (delegation tree, cascading revocation, depth 8) | `capability.zig` | ✅ |
| Policy Engine (whitelist rules, Allow/Deny/Audit/RateLimit) | `policy_engine.zig` | ✅ |
| AI Capsule Manager (restricted caps, memory quota, TTL, rollback) | `ai_capsule.zig` | ✅ |
| IPC (Channel-based, Zircon-inspired, handle transfer) | `ipc.zig` | ✅ |
| IOMMU (Intel VT-d, DMA protection, DMAR via ACPI) | `iommu.zig` | ✅ |
| Intent Layer (5-phase dispatch, 72-byte Intent, PND nonce, Firewall) | `poler/intent.zig` | ✅ |
| Dual-Personality Subsystem (NT API + POSIX API + POLER + AI) | `subsystem/` | ✅ |
| Object Manager (13 types, unified namespace, per-process handles) | `object_manager.zig` | ✅ |
| Syscall Integration (syscall→Intent→Subsystem bridge) | `syscall_integration.zig` | ✅ |
| Kernel Integration (VFS↔FAT32, Process Mgr, ACL↔Auth, COW fork) | `kernel_integrate.zig` | ✅ |
| **VFS Layer v1.0** (VfsOps vtable, mount table, unified path, FAT32+CPIO drivers) | `vfs.zig` | ✅ **NEW** |
| Interactive Shell (ls, cat, mkdir, touch, write, rm, disk, caps, run) | `main64.zig` | ✅ |
| **Unified Input** (PS/2 keyboard + Serial COM1 via `hal.readKey()`) | `hal.zig` | ✅ **FIXED** |

---

## 5. ИЗВЕСТНЫЕ ПРОБЛЕМЫ И БАГИ

### 5.1. Критические (блокируют нормальную работу)

| # | Проблема | Статус | Решение |
|---|----------|--------|---------|
| 1 | **Клавиатура не вводит текст в shell** | ✅ **ИСПРАВЛЕНО** | Добавлена `hal.readKey()` — единая функция ввода (kbd_pop + Serial.readChar). Shell теперь использует `readKey()` |
| 2 | **Нет virtio-blk при загрузке с -cdrom** | ✅ **ИСПРАВЛЕНО** | `run64-iso` теперь всегда включает `-drive file=disk.img,if=virtio,format=raw` |
| 3 | **VFS не реализован** | ✅ **ИСПРАВЛЕНО** | Создан `vfs.zig` с VfsOps vtable, mount table, FAT32+CPIO драйверами |

### 5.2. Частичные реализации

| # | Компонент | Проблема |
|---|-----------|----------|
| 1 | IOMMU | Драйвер существует, но нужны 4-level page tables для production |
| 2 | SMP | Код завершён, но нужно стресс-тестирование (1ч+), TSC sync, TLB shootdown |
| 3 | POSIX signals | Фреймворк существует, но доставка сигналов не реализована |
| 4 | epoll/select/poll | Заглушки в posix_api, не функциональны |
| 5 | GRUB cfg version mismatch | Некоторые grub.cfg файлы показывают "v0.7.0" при ядре v0.9.0 |

### 5.3. Исправленные баги (предыдущие сессии)

| # | Баг | Исправление |
|---|-----|-------------|
| 1 | Scheduler race condition | `createTaskSafe()` с `cliSave()/stiSet()`, state=Killed при init, `@fence(.release)` |
| 2 | El Torito boot record | `grub-mkrescue --directory` для корректного GRUB модуля |
| 3 | Hardcoded paths в build скриптах | `build-iso-local.sh`: динамические пути, GRUB auto-detection |
| 4 | `@fence(.Release)` → `.release` | Zig 0.13.0 использует lowercase enum values |
| 5 | `cli()` return type | Разделён на `cli()` (void) + `cliSave()` (bool) для обратной совместимости |
| 6 | **Keyboard input disconnect** | Добавлена `hal.readKey()` (kbd_pop + Serial.readChar). Shell использует `readKey()` вместо `Serial.readChar()` |
| 7 | **virtio-blk missing in run64-iso** | `build.zig`: `run64-iso` теперь включает `-drive file=disk.img,if=virtio,format=raw` |
| 8 | **No VFS abstraction** | Создан `vfs.zig` с VfsOps vtable, mount table, FAT32+CPIO драйверами |

---

## 6. ДОРОЖНАЯ КАРТА v1.1.0 (5 ШАГОВ СЕМАНТИЧЕСКОЙ БЕЗОПАСНОСТИ)

> Это roadmap следующего релиза, поверх уже работающего v0.9.0

### Шаг 1: Intent Layer — ЗАВЕРШЁН ✅
- Intent Dispatcher (v1.1.0) инициализируется при загрузке
- 72-байтная структура Intent (category/action/caller_pid/target_handle/args[6]/nonce)
- I/O interception через 5-фазный пайплайн
- 40+ IntentAction операций (FS_OPEN, PROC_CREATE, MEM_MMAP, NET_CONNECT, etc.)

### Шаг 2: POLER Firewall Integration — ЗАВЕРШЁН ✅
- PND v8 tensor algebra (`⊗ε`) проверяет каждый Intent
- Per-caller Firewall instances с SipHash PRF
- Cognitive cycle anomaly detection (поведенческий анализ)
- Token bucket rate limiting

### Шаг 3: Object Table + Capability Handles — В ПРОЦЕССЕ ⚠️
- Zircon-style descriptor table (per-process handle table)
- access_mask (u32) на каждый handle
- 13 типов объектов (File, Directory, Device, Event, Mutant, Semaphore, Timer, Section, Port, Token, Key, Process, Thread)
- **Не завершено**: CNode/handle table полная интеграция с Intent dispatch

### Шаг 4: VFS ↔ DynLinker Integration — НЕ НАЧАТ ❌
- VFS абстрактный интерфейс (mount/open/read/write/close, inode)
- Per-process namespace (root_fs_inode в Task)
- .so integrity verification через SHA-256 (уже в dynlinker.zig)
- RSA-OAEP верификация через rsa_oaep.zig
- DT_NEEDED auto-loading из /lib/ через VFS/FAT32

### Шаг 5: Thread Creation + FS_BASE Switching — ЧАСТИЧНО ⚠️
- NtCreateThread / clone syscalls
- FS_BASE/GS_BASE switching (TLS support уже в scheduler.zig)
- Per-thread TCB auto-allocation
- **Не завершено**: NtCreateThread implementation, POSIX clone()

---

## 7. ДОЛГОСРОЧНАЯ ДОРОЖНАЯ КАРТА (из ROADMAP.md)

### Приоритеты

| Приоритет | Компонент | Статус | Зависимости |
|-----------|-----------|--------|-------------|
| 🔴 P1 | SMP (многоядерность) | ✅ Код завершён, нужны стресс-тесты | — |
| 🟠 P2 | VFS (виртуальная файловая система) | ❌ Не начат | SMP |
| 🟠 P3 | ext2 → POLER-FS | ❌ Не начат | VFS, AHCI |
| 🟡 P4 | Сетевой стек (virtio-net, e1000, TCP/UDP) | ❌ Не начат | SMP |
| 🟡 P5 | AHCI/SATA драйвер | ❌ Не начат | PCI, DMA |

### Версионирование

| Версия | Веха | Статус |
|--------|------|--------|
| v0.7.0 | Базовое ядро + документация | ✅ Завершено |
| v0.8.0 | Dual-personality (NT+POSIX) | ✅ Завершено |
| v0.9.0 | Semantic Security (Intent+Firewall) | ✅ Завершено |
| v1.0.0 | SMP + VFS + FS + Network | 🔲 Планируется |
| v1.1.0 | Semantic Security завершение (Steps 3-5) | ⚠️ В процессе |
| v2.0.0 | Shim-архитектура + совместимость | 🔲 Долгосрочная цель |

### Shim-архитектура (v2.0.0, долгосрочная)

Механизм: Shim как обязательная библиотека (Wine-подход):
1. Loader определяет тип бинарника (PE/ELF)
2. Парсит зависимости (DT_NEEDED / IAT)
3. Подменяет системные библиотеки на `poler-*` shim'ы
4. Мапит shim в адресное пространство процесса
5. Связывает IAT/GOT/PLT с точками входа шима
6. Регистрирует капсулу (`capsule_type = windows/linux`)
7. Запускает процесс

Страховка для статических бинарников: per-process syscall table → upcall в shim handler → native syscall → результат. 2 ring switches.

Оптимизация: VDSO page (pid, tid, timestamp, capsule_id) — 0 ring switches для чтения.

---

## 8. АУДИТ БЕЗОПАСНОСТИ (из CAPABILITY-DELEGATION-AUDIT-v1.0.md)

**Security Score: 7.5/10** (до P0/P1 фиксов: 5.0/10)

### Выявленные уязвимости (из сессии анализа):

1. **Ambient Authority** — процесс с CAP_FILE_READ имеет доступ ко ВСЕМ файлам, а не только к конкретным. Решено через Intent Layer + per-handle access_mask (Phase 4).

2. **VFS-DynLinker Disconnect** — .so файлы загружаются dynlinker без верификации через Intent pipeline. SHA-256 integrity check существует, но не интегрирован с VFS/police engine. (Step 4 roadmap).

3. **No Multithreading/TLS Isolation** — нет NtCreateThread/clone, нет per-thread capability isolation. (Step 5 roadmap).

### Рекомендации аудита:

- HMAC-SHA256 для POLER token MAC (вместо простого SipHash)
- 4-level IOMMU page tables для production
- CNode/handle table полная интеграция
- Per-handle audit logging для чувствительных операций

---

## 8.1. VFS АРХИТЕКТУРА (v0.9.0, НОВЫЙ МОДУЛЬ)

### Структура VFS (vfs.zig, ~1050 строк)

```
POSIX syscalls ──┐
                  ├──→ VFS Core ──→ Mount Table ──┬──→ Fat32VfsOps ──→ Fat32Fs ──→ virtio_blk
NT syscalls ────┘     │                          ├──→ CpioVfsOps  ──→ Ramdisk (memory)
                      ├──→ Path Resolution (unified /posix + \??\C:\nt)
                      ├──→ File Handle Table (filesystem-agnostic)
                      └──→ VfsInode abstraction
```

### Ключевые компоненты

| Компонент | Описание |
|-----------|----------|
| `VfsOps` | Vtable (13 функций): open/read/write/close/seek/stat/chmod/mkdir/rmdir/unlink/rename/listDir/sync |
| `VfsFileHandle` | Файловый дескриптор (opaque: ops + fs_instance + fs_private) |
| `VfsInode` | Файловая метаинформация (ino, file_type, size, mode, timestamps) |
| `VfsMount` | Запись в mount table (path prefix → fs_ops + fs_instance) |
| `VfsStat` | POSIX-совместимый stat (st_dev, st_ino, st_mode, st_size, timestamps) |
| `Fat32VfsOps` | Драйвер FAT32: обёртка над fat32.zig |
| `CpioVfsOps` | Драйвер CPIO: read-only ramdisk из initrd |
| `resolvePath()` | Унифицированное разрешение путей (/posix и \??\C:\nt) |

### Mount table (пример после загрузки)

```
/          → Fat32VfsOps (virtio-blk, read/write)
/initrd    → CpioVfsOps  (memory, read-only)
```

### Что ещё нужно для VFS

- Wire POSIX/NT subsystems через `vfs.open()` вместо прямых `ki.vfsOpen()` → `fat32.getFs()`
- Wire NT subsystem: `NtReadFile`/`NtWriteFile` через VFS
- Per-process mount namespace (для контейнеров/shim-изоляции)
- ProcFS драйвер (виртуальная ФС для /proc/pid, /proc/cpuinfo)
- Inode cache / dcache (кэш разрешения путей)

---

## 9. КЛЮЧЕВЫЕ ПАТТЕРНЫ КОДА

### 9.1. Callback-based dependency breaking

Циклические импорты (hal↔scheduler, hal↔vmm, scheduler↔dynlinker) разрешены через function pointer callbacks, регистрируемые при init:

```zig
// В hal.zig:
pub var scheduler_tick_callback: ?*const fn () callconv(.c) void = null;
pub var cow_handler_callback: ?*const fn (u64) void = null;
pub var virtio_irq_callback: ?*const fn () callconv(.c) void = null;
pub var on_task_exit_callback: ?*const fn (u16) callconv(.c) void = null;
```

### 9.2. Freestanding kernel

Нет `std` импорта в ядре. Весь I/O через HAL примитивы (Serial, framebuffer). В poler_core.zig используется `const std = @import("std")` только для тестов.

### 9.3. Identity-mapped kernel

Physical = virtual at 0x100000. Нет higher-half kernel. Per-process PML4 для user tasks.

### 9.4. Per-process isolation

Каждый user process получает: собственный PML4, handle table, capability set, Intent per-caller Firewall instance.

### 9.5. Zig 0.13.0 specifics

- Enum values: lowercase `.release` (не `.Release`)
- `@fence()` ordering: `.acquire`, `.release`, `.acq_rel`, `.seq_cst`
- `@atomicRmw()` для lock-free операций
- `callconv(.c)` для callback function pointers
- `extern struct` для фиксированного layout (Intent)
- No `std` в kernel code (freestanding target)

---

## 10. QEMU ЗАПУСК И ТЕСТИРОВАНИЕ

### Стандартный запуск (ISO):
```bash
qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio -no-reboot
```

### С virtio-blk (блочное устройство):
```bash
qemu-system-x86_64 -cdrom poler-os64.iso -drive file=disk.img,format=raw,if=virtio -m 256M -serial stdio -no-reboot
```

### SMP тестирование:
```bash
qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -smp 2 -serial stdio -no-reboot
```

### IOMMU тестирование:
```bash
qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -machine q35 -device intel-iommu,intremap=on -serial stdio -no-reboot
```

### Сборка через Zig:
```bash
zig build run64          # 64-bit kernel, QEMU без ISO
zig build run64-iso      # 64-bit kernel, ISO boot
zig build run64-blk      # 64-bit kernel с virtio-blk
zig build run64-vtd      # 64-bit kernel с IOMMU
```

---

## 11. ИНСТРУКЦИИ ДЛЯ AI-АССИСТЕНТА

При работе с POLER-OS следуй этим правилам:

1. **Язык**: Отвечай на том же языке, что и пользователь (русский/украинский/английский).

2. **Zig 0.13.0**: Всегда используй синтаксис Zig 0.13.0. Не предлагай код для других версий.

3. **Freestanding**: Ядро работает без std. Не используй `std.mem`, `std.fmt`, `std.heap` в kernel code.

4. **Точность архитектуры**: Не путай shim-архитектуру (v2.0.0, userspace) с текущей dual-personality реализацией (v0.9.0, kernel-space). Сейчас NT и POSIX реализованы внутри ядра — shim будет в userspace позже.

5. **Intent-first**: Любое изменение I/O путей должно проходить через Intent Layer. Не добавляй прямые вызовы FAT32/VirtIO в обход Intent pipeline.

6. **Capability consistency**: Новые syscall handlers должны проверять capabilities через Policy Engine + Intent dispatch, не через прямые проверки `pcb.acl_capabilities`.

7. **Callback pattern**: Для новых зависимостей используй callback function pointers, регистрируемые при init, чтобы избежать циклических импортов.

8. **Тестирование**: Все изменения должны проверяться в QEMU. Используй соответствующий `zig build run64-*` target.

9. **Документация**: Обновляй ROADMAP.md и CAPABILITY-DELEGATION-AUDIT после значимых изменений.

10. **Безопасность**: Security score 7.5/10 — цель v1.0.0 — 9.0/10. Каждое изменение должно учитывать влияние на безопасность.

---

## 12. ФИЛОСОФИЯ ПРОЕКТА

> **«Программа — гость, а не хозяин»**

POLER-OS не пытается быть ещё одним Linux или ещё одной Windows. Это третья парадигма: ОС, где программа по умолчанию не имеет никаких прав, и каждое действие должно быть явно авторизовано через Intent. Dual-personality — это не эмуляция (как WINE или WSL1), а нативная поддержка обоих API на уровне syscall dispatcher. Криптографический фундамент (PND v8, RSA-OAEP, POLER-CTR) обеспечивает целостность на всех уровнях.

**Microsoft не диктует правила. Правила диктует архитектура.**
