# POLER-OS — Детальный план реализации

> Версия документа: 2026-07-17  
> Целевая версия ядра: v0.8.0 (SMP) → v0.9.0 (VFS) → v1.0.0 (Network)  
> Язык реализации: Zig 0.13.0, freestanding, x86_64  
> Загрузчик: GRUB2 / Multiboot2  
> Тестовая среда: QEMU 7.0+

---

## 1. Критические проблемы (P0)

### 1.1. Отсутствует `spinlock.zig`

**Текущее состояние:**  
`smp.zig` импортирует `spinlock.zig` на строке 30 и использует `spinlock.Spinlock` на строке 77. Файл **физически отсутствует** в `src64/`. В то же время `hal.zig` содержит простейшие функции `spinLock()`/`spinUnlock()`, работающие с `*u32` через `@atomicRmw`. Документация SMP_SPECIFICATION.md описывает Spinlock с PAUSE, tryAcquire и SpinlockGuard RAII — но этого кода нет.

**Шаги по исправлению:**

1. Создать файл `src64/spinlock.zig`
2. Реализовать структуру `Spinlock` с методами `acquire()`, `release()`, `tryAcquire()`
3. Реализовать `SpinlockGuard` (RAII) для автоматического освобождения
4. Обновить `smp.zig`: заменить `var smp_lock: spinlock.Spinlock = .{};` (уже корректный синтаксис)
5. Обновить `hal.zig`: делегировать `serial_lock` к новому типу `spinlock.Spinlock`
6. Добавить юнит-тест для корректности lock/unlock

**Оценка времени:** 2–3 человеко-часа

**Минимальный рабочий код:**

```zig
// ============================================================================
// POLER-OS Spinlock — x86_64
// ============================================================================
// Ticket-less spinlock with PAUSE hint, tryAcquire, and SpinlockGuard RAII.
// Compatible with the API used in smp.zig: `var lock: Spinlock = .{};`
// ============================================================================

const std = @import("std");

pub const Spinlock = struct {
    locked: u32 = 0,

    /// Acquire the spinlock. Spins with PAUSE until the lock is available.
    /// Uses @atomicRmw with .Xchg for correct memory ordering.
    pub fn acquire(self: *Spinlock) void {
        while (@atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) != 0) {
            // Spin with PAUSE hint — reduces power consumption and improves
            // performance on hyperthreaded CPUs by giving the other logical
            // processor a chance to use the execution resources.
            asm volatile ("pause");
        }
    }

    /// Release the spinlock.
    pub fn release(self: *Spinlock) void {
        @atomicStore(u32, &self.locked, 0, .release);
    }

    /// Try to acquire the spinlock without blocking.
    /// Returns true if the lock was successfully acquired.
    pub fn tryAcquire(self: *Spinlock) bool {
        return @atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) == 0;
    }

    /// Check if the spinlock is currently held (non-atomic, diagnostic only).
    pub fn isHeld(self: *const Spinlock) bool {
        return @atomicLoad(u32, &self.locked, .unordered) != 0;
    }
};

/// RAII guard that automatically releases a Spinlock when it goes out of scope.
/// Usage:
///   {
///       var guard = SpinlockGuard.acquire(&my_lock);
///       // critical section
///       defer guard.release();
///   }
pub const SpinlockGuard = struct {
    lock: *Spinlock,

    /// Acquire the lock and return a guard.
    pub fn acquire(lock: *Spinlock) SpinlockGuard {
        lock.acquire();
        return SpinlockGuard{ .lock = lock };
    }

    /// Release the lock. Can be called manually, or deferred to scope exit.
    pub fn release(self: *SpinlockGuard) void {
        self.lock.release();
    }
};

// ============================================================================
// Unit Tests (run with: zig test spinlock.zig -target x86_64-linux)
// ============================================================================

test "Spinlock acquire/release basic" {
    var lock: Spinlock = .{};
    try std.testing.expect(!lock.isHeld());
    lock.acquire();
    try std.testing.expect(lock.isHeld());
    lock.release();
    try std.testing.expect(!lock.isHeld());
}

test "Spinlock tryAcquire" {
    var lock: Spinlock = .{};
    try std.testing.expect(lock.tryAcquire());
    try std.testing.expect(!lock.tryAcquire()); // Already held
    lock.release();
    try std.testing.expect(lock.tryAcquire()); // Available again
    lock.release();
}

test "SpinlockGuard RAII" {
    var lock: Spinlock = .{};
    {
        var guard = SpinlockGuard.acquire(&lock);
        try std.testing.expect(lock.isHeld());
        guard.release();
    }
    try std.testing.expect(!lock.isHeld());
}
```

**Критерии готовности:**
- `zig build` компилирует ядро без ошибок
- `smp.zig` успешно импортирует `spinlock.Spinlock`
- Юнит-тест `zig test src64/spinlock.zig` проходит
- `hal.zig:serial_lock` может быть заменена на `spinlock.Spinlock` без потери совместимости

---

### 1.2. Отсутствует `atomic.zig`

**Текущее состояние:**  
SMP_SPECIFICATION.md описывает `AtomicCounter`, `AtomicFlag`, `cas()`, `fetchAdd()`, `spinWait()` и другие. Файл не существует. `smp.zig` уже использует `@atomicLoad`/`@atomicStore` напрямую (строки 296, 300, 368, 397–399), но это «сырые» встроенные функции Zig без удобной абстракции. Для `scheduler.zig` (per-CPU очереди) потребуется `AtomicCounter` и `AtomicFlag`.

**Шаги по исправлению:**

1. Создать файл `src64/atomic.zig`
2. Реализовать `AtomicCounter` (increment, decrement, add, sub, get, set)
3. Реализовать `AtomicFlag` (trySet, clear, isSet на основе CAS)
4. Добавить helper-функции: `cas()`, `fetchAdd()`, `memoryBarrier()`
5. Добавить юнит-тесты

**Оценка времени:** 2–3 человеко-часа

**Минимальный рабочий код:**

```zig
// ============================================================================
// POLER-OS Atomic Operations — x86_64
// ============================================================================
// Thin wrappers around Zig's built-in atomics for kernel-wide consistency.
// All operations use Sequentially Consistent ordering by default unless
// explicitly overridden, which is the safest default for kernel code.
// ============================================================================

pub fn AtomicCounter(comptime T: type) type {
    return struct {
        value: T align(@alignOf(T)),

        const Self = @This();

        pub fn init(val: T) Self {
            return .{ .value = val };
        }

        pub fn increment(self: *Self) T {
            return @atomicRmw(T, &self.value, .Add, 1, .seq_cst);
        }

        pub fn decrement(self: *Self) T {
            return @atomicRmw(T, &self.value, .Sub, 1, .seq_cst);
        }

        pub fn add(self: *Self, operand: T) T {
            return @atomicRmw(T, &self.value, .Add, operand, .seq_cst);
        }

        pub fn sub(self: *Self, operand: T) T {
            return @atomicRmw(T, &self.value, .Sub, operand, .seq_cst);
        }

        pub fn get(self: *const Self) T {
            return @atomicLoad(T, &self.value, .seq_cst);
        }

        pub fn set(self: *Self, val: T) void {
            @atomicStore(T, &self.value, val, .seq_cst);
        }

        /// Compare-and-swap (strong). Returns true if the swap succeeded.
        pub fn compareAndSwap(self: *Self, expected: T, desired: T) bool {
            return @cmpxchgStrong(T, &self.value, expected, desired, .seq_cst, .seq_cst) == null;
        }
    };
}

pub const AtomicU32 = AtomicCounter(u32);
pub const AtomicU64 = AtomicCounter(u64);
pub const AtomicBool = AtomicCounter(bool);

/// Atomic flag — a boolean that can be atomically set/cleared.
/// Uses CAS for set, atomic store for clear.
pub const AtomicFlag = struct {
    flag: u32 align(4) = 0,

    /// Try to set the flag. Returns true if we were the one to set it.
    pub fn trySet(self: *AtomicFlag) bool {
        return @cmpxchgStrong(u32, &self.flag, 0, 1, .seq_cst, .seq_cst) == null;
    }

    /// Clear the flag.
    pub fn clear(self: *AtomicFlag) void {
        @atomicStore(u32, &self.flag, 0, .seq_cst);
    }

    pub fn isSet(self: *const AtomicFlag) bool {
        return @atomicLoad(u32, &self.flag, .seq_cst) != 0;
    }
};

/// Full memory barrier (mfence on x86_64)
pub fn memoryBarrier() void {
    asm volatile ("mfence" ::: "memory");
}

/// Read barrier (lfence on x86_64)
pub fn readBarrier() void {
    asm volatile ("lfence" ::: "memory");
}

/// Write barrier (sfence on x86_64)
pub fn writeBarrier() void {
    asm volatile ("sfence" ::: "memory");
}

/// Spin-wait hint (equivalent to x86 PAUSE)
pub fn spinWait() void {
    asm volatile ("pause");
}
```

**Критерии готовности:**
- Файл компилируется без ошибок
- Юнит-тесты `AtomicCounter`, `AtomicFlag`, CAS проходят
- Совместим с использованием `@atomicLoad`/`@atomicStore` в `smp.zig` (не ломает существующий код)

---

### 1.3. `scheduler.zig` не имеет per-CPU очередей

**Текущее состояние:**  
`SMP_SPECIFICATION.md` (раздел 2.7) утверждает, что per-CPU scheduler реализован: `cpu_run_queues[MAX_CPUS]CpuRunQueue`, `cpu_current_task[MAX_CPUS]usize`, `cpu_current_cr3[MAX_CPUS]u64`. В реальности `scheduler.zig` использует **глобальные** переменные: `current_task_id: usize = 0`, `current_cr3: u64 = 0`. При этом `smp.zig` строка 385 ссылается на `scheduler.cpu_run_queues[cpu_id].count` — **ядро не скомпилируется**, если SMP код подключён.

**Шаги по исправлению:**

1. Добавить в `scheduler.zig` структуру `CpuRunQueue` (очередь задач + Spinlock)
2. Создать массив `pub var cpu_run_queues: [smp.MAX_CPUS]CpuRunQueue`
3. Создать массив `pub var cpu_current_task: [smp.MAX_CPUS]usize`
4. Создать массив `pub var cpu_current_cr3: [smp.MAX_CPUS]u64`
5. Обновить `schedule()` — использовать `smp.currentCpuId()` для индексации per-CPU данных
6. Реализовать load balancing (миграция задач при дисбалансе)
7. Добавить поле `affinity: u8` в `Task` (0xFF = любой CPU)

**Оценка времени:** 1–2 человеко-дня (8–16 часов)

**Ключевой код (структура CpuRunQueue):**

```zig
const spinlock = @import("spinlock.zig");
const smp = @import("smp.zig");

/// Per-CPU run queue with integrated spinlock for SMP safety.
pub const CpuRunQueue = struct {
    lock: spinlock.Spinlock = .{},
    tasks: [MAX_TASKS_PER_CPU]?usize = .{null} ** MAX_TASKS_PER_CPU,
    count: u32 = 0,
    head: u32 = 0,
    tail: u32 = 0,

    pub const MAX_TASKS_PER_CPU = 16;

    pub fn enqueue(self: *CpuRunQueue, task_id: usize) bool {
        const guard = spinlock.SpinlockGuard.acquire(&self.lock);
        defer guard.release();
        if (self.count >= MAX_TASKS_PER_CPU) return false;
        self.tasks[self.tail] = task_id;
        self.tail = (self.tail + 1) % MAX_TASKS_PER_CPU;
        self.count += 1;
        return true;
    }

    pub fn dequeue(self: *CpuRunQueue) ?usize {
        const guard = spinlock.SpinlockGuard.acquire(&self.lock);
        defer guard.release();
        if (self.count == 0) return null;
        const task_id = self.tasks[self.head];
        self.tasks[self.head] = null;
        self.head = (self.head + 1) % MAX_TASKS_PER_CPU;
        self.count -= 1;
        return task_id;
    }
};

pub var cpu_run_queues: [smp.MAX_CPUS]CpuRunQueue = .{};
pub var cpu_current_task: [smp.MAX_CPUS]usize = .{0} ** smp.MAX_CPUS;
pub var cpu_current_cr3: [smp.MAX_CPUS]u64 = .{0} ** smp.MAX_CPUS;
```

**Критерии готовности:**
- Ядро компилируется с `smp.zig` без ошибок
- `schedule()` использует `smp.currentCpuId()` для получения per-CPU данных
- `ap_entry_zig()` может корректно обращаться к `cpu_run_queues[cpu_id]`

---

### 1.4. Тестирование SMP в QEMU

**Текущее состояние:**  
AP trampoline код написан и исправлен (lgdt из фиксированного data area 0x8100), но **ни разу не запускался** в QEMU с `-smp 2`. Есть высокий риск triple fault из-за ошибок в 16→32→64 переходе, неверных GDT-дескрипторов, или проблем с paging.

**План тестирования:**

#### Команда запуска

```bash
# Базовый SMP-тест (2 CPU, 256MB RAM, serial output)
LOCAL="/home/z/my-project/.local"
export PATH="$LOCAL/bin:$PATH"
export LD_LIBRARY_PATH="$LOCAL/lib:${LD_LIBRARY_PATH:-}"

# Сначала собрать ISO
cd /home/z/my-project/zig-kernel
$LOCAL/bin/zig build -Doptimize=ReleaseSmall
bash build-iso-local.sh

# Запуск QEMU с SMP
qemu-system-x86_64 \
    -cdrom poler-os64.iso \
    -m 256M \
    -smp 2 \
    -serial stdio \
    -display none \
    -no-reboot \
    -d guest_errors,int \
    -D /tmp/qemu-smp-debug.log \
    2>&1 | tee /tmp/poler-smp-output.log
```

#### Ожидаемый вывод (успех)

```
[ACPI] MADT: Found 2 CPU(s)
[ACPI]   CPU 0: APIC ID=0, Flags=0x01 (BSP, enabled)
[ACPI]   CPU 1: APIC ID=1, Flags=0x01 (enabled)
[SMP] BSP Local APIC ID: 0x0
[SMP] BSP GSBASE set to 0x...
[SMP] Setting up AP trampoline at 0x8000...
[SMP] Starting AP 1 (APIC_ID=0x1)
[SMP] AP 1 entering ap_entry_zig()
[SMP] AP 1 ready (APIC_ID=0x1)
[SMP] AP 1 is ready
[SMP] All CPUs online: 2
```

#### Точки отладки при triple fault

| Симптом | Причина | Где искать |
|---------|---------|-----------|
| CPU reset сразу после SIPI | Неверный GDT в trampoline | `boot_smp.S` — проверить `lgdt` из адреса 0x8100 |
| #GP после перехода в protected mode | Неверный 32-bit code/data descriptor | `hal.zig` — проверить GDT entry 0x28, 0x30 |
| #PF при включении paging | Неверный CR3 или page tables | `smp.zig` — проверить `data.cr3` |
| Triple fault после перехода в 64-bit | Неверный 64-bit code descriptor | `hal.zig` — GDT entry 0x08 |
| AP зависает в idle loop | APIC не инициализирован | `ap_entry_zig()` — проверить `hal.APIC.init()` |

#### Отладка через GDB

```bash
# Terminal 1: QEMU с GDB stub
qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -smp 2 \
    -serial stdio -display none -no-reboot -s -S

# Terminal 2: GDB
gdb
(gdb) target remote :1234
(gdb) break ap_entry_zig
(gdb) continue
# Когда остановится — проверить регистры:
(gdb) info registers
(gdb) x/10i $rip
```

**Критерии готовности:**
- Оба CPU обнаружены через MADT
- AP успешно переходит в 64-bit long mode
- Оба CPU печатают `[SMP] AP N ready`
- `online_cpus == 2`
- Нет triple fault при загрузке
- Нет deadlock на serial_lock

---

## 2. Важные задачи (P1)

### 2.1. Сводная таблица

| Задача | Зачем | Оценка сложности | Предлагаемый подход | Зависимости | Ожидаемый результат |
|--------|-------|------------------|---------------------|-------------|---------------------|
| **VFS (Virtual File System)** | Абстракция над FAT32/ext2 — без неё нельзя добавить другие FS, mount, open/close | Средняя (1–2 недели) | Интерфейс `VfsOps` + inode + mount table + path resolver | Spinlock, PMM | `mount()`, `open()`, `read()`, `write()`, `close()` работают с любой FS |
| **Очистка legacy-файлов** | `src/`, `boot/`, `mm/`, `arch/`, `drivers/` — v0.1.0 мусор, не используется 64-bit ядром | Лёгкая (2 часа) | Переместить в `legacy/` ветку, удалить из main | — | В `src64/` только актуальный код, git чист |
| **Убрать лимит PMM 4GB** | `MAX_MEM_SUPPORTED = 0x100000000` — системы с >4GB RAM не используют лишнее | Средняя (1–2 дня) | Динамический bitmap на основе реального объёма RAM из Multiboot2 | VMM | PMM поддерживает до 1TB RAM |

### 2.2. VFS — Технические заметки

#### Интерфейс VfsOps

```zig
// src64/vfs.zig

pub const VfsOps = struct {
    mount: *const fn (device: *BlockDevice, opts: MountOptions) anyerror!FileSystem,
    unmount: *const fn (fs: *FileSystem) void,

    open: *const fn (fs: *FileSystem, path: []const u8, flags: OpenFlags) anyerror!File,
    close: *const fn (file: *File) void,

    read: *const fn (file: *File, buf: []u8, offset: u64) anyerror!usize,
    write: *const fn (file: *File, buf: []const u8, offset: u64) anyerror!usize,

    mkdir: *const fn (fs: *FileSystem, path: []const u8) anyerror!void,
    unlink: *const fn (fs: *FileSystem, path: []const u8) anyerror!void,
    readdir: *const fn (dir: *File, entries: []DirEntry) anyerror!usize,

    stat: *const fn (fs: *FileSystem, path: []const u8) anyerror!InodeInfo,
};
```

#### Структура Inode

```zig
pub const Inode = struct {
    ino: u64,            // Unique inode number
    mode: InodeMode,     // File, Directory, Symlink, Device
    size: u64,           // File size in bytes
    nlinks: u32,         // Hard link count
    uid: u32,            // Owner UID
    gid: u32,            // Owner GID
    atime: u64,          // Access time (Unix timestamp)
    mtime: u64,          // Modification time
    ctime: u64,          // Change time
    blk_size: u32,       // Block size for I/O
    blocks: u64,         // Number of blocks allocated
    fs_priv: u64,        // Filesystem-private data (e.g., FAT32 cluster)

    const InodeMode = packed struct {
        type: enum(u4) {
            file = 0,
            directory = 1,
            symlink = 2,
            block_device = 3,
            char_device = 4,
        },
        perms: packed struct {
            owner_r: bool,
            owner_w: bool,
            owner_x: bool,
            group_r: bool,
            group_w: bool,
            group_x: bool,
            other_r: bool,
            other_w: bool,
            other_x: bool,
        },
        setuid: bool,
        setgid: bool,
        sticky: bool,
    };
};
```

#### Mount table

```zig
pub const MountPoint = struct {
    path: [256]u8,         // Mount path (e.g., "/")
    path_len: u16,
    fs: *FileSystem,       // Mounted filesystem
    ops: *const VfsOps,    // Operations table
    device: ?*BlockDevice, // Underlying block device
    parent: ?*MountPoint,  // Parent mount (for nested mounts)
};

pub const MAX_MOUNT_POINTS = 8;
pub var mount_table: [MAX_MOUNT_POINTS]MountPoint = undefined;
pub var mount_count: usize = 0;
```

#### Path resolution

```zig
/// Resolve a path to an inode, traversing mount points.
/// Supports: absolute paths, ".", "..", symlinks (future).
pub fn resolvePath(path: []const u8) anyerror!*Inode {
    // 1. Find the mount point that is the longest prefix of path
    // 2. Delegate to the filesystem's resolvePath()
    // 3. Handle ".." crossing mount boundaries
    _ = path;
    return error.NotImplemented;
}
```

#### Интеграция с FAT32

Существующий `fat32.zig` будет обёрнут в `VfsOps`:

```zig
pub const fat32_vfs_ops: VfsOps = .{
    .mount = fat32Mount,
    .unmount = fat32Unmount,
    .open = fat32Open,
    .close = fat32Close,
    .read = fat32Read,
    .write = fat32Write,
    .mkdir = fat32Mkdir,
    .unlink = fat32Unlink,
    .readdir = fat32Readdir,
    .stat = fat32Stat,
};
```

Это позволяет оставить `fat32.zig` практически без изменений — адаптер транслирует VFS вызовы в FAT32 API.

#### Связь с shim-архитектурой

VFS с per-process namespace — фундамент для shim. Каждый процесс получает `root_inode`, который может указывать на изолированное поддерево. Shim-библиотека транслирует `C:\Windows\System32\` в `/capsules/{pid}/C/Windows/System32/` через VFS mount в изолированное пространство.

---

### 2.3. Очистка legacy-файлов

**Предлагаемая стратегия:** Создать ветку `archive/legacy-32bit` и удалить legacy-файлы из `main`.

**Файлы к удалению из main:**

| Путь | Причина |
|------|---------|
| `src/` (весь каталог) | 32-bit ядро v0.1.0, не используется |
| `boot/boot.zig` | Zig inline MBR boot, заброшен |
| `mm/pmm.zig` | Legacy PMM без Multiboot2 mmap |
| `arch/x86_64/idt.zig` | Незавершённый IDT, содержит TODO на Rust |
| `drivers/virtio.zig` | Дубликат `src64/virtio_blk.zig` + `src64/pci.zig` |
| `drivers/vga.zig` | VGA text mode — заменён на framebuffer |
| `drivers/framebuffer.zig` | Дубликат `src64/framebuffer.zig` |
| `main.zig` | Старый v0.1.0 kernel main |
| `build_test.zig` | Альтернативный test build (минимальный 32-bit) |

**Файлы к сохранению:**

| Путь | Причина |
|------|---------|
| `src64/` (всё) | Актуальное 64-bit ядро |
| `build.zig` | Основной build system |
| `build-iso*.sh` | ISO сборка |
| `run-qemu*.sh` | QEMU запуск |
| `iso/`, `iso-efi/`, `iso-minimal/` | GRUB конфиги |
| `docs/` | Документация |

**Процедура:**

```bash
# 1. Сохранить в архивной ветке
git checkout -b archive/legacy-32bit
git push origin archive/legacy-32bit
git checkout main

# 2. Удалить legacy из main
git rm -r src/ boot/ mm/ arch/ drivers/ main.zig build_test.zig
git commit -m "chore: remove legacy 32-bit code (archived in archive/legacy-32bit)"
git push origin main
```

---

### 2.4. Убрать лимит PMM 4GB

**Текущее ограничение:**

```zig
// pmm64.zig
const MAX_MEM_SUPPORTED: u64 = 0x100000000; // 4GB for Phase 1
const MAX_PAGES: u64 = MAX_MEM_SUPPORTED / PAGE_SIZE;
var bitmap: [MAX_PAGES / 8]u8 = undefined; // 128 KB static bitmap
```

**Проблема:** Статический массив `bitmap` на 128KB размещается в BSS. Для поддержки 1TB RAM нужен bitmap на 32MB — это слишком много для BSS, но можно выделить динамически.

**Предлагаемое решение:**

```zig
// pmm64.zig — обновлённая версия

const PAGE_SIZE: u64 = 4096;

/// Dynamic bitmap: pointer + size, allocated from usable memory
/// at init time based on actual RAM detected via Multiboot2.
var bitmap_ptr: [*]u8 = undefined;
var bitmap_size: u64 = 0;     // Size in bytes
var max_page: u64 = 0;        // Highest page index
var highest_addr: u64 = 0;    // Highest physical address detected

var total_ram_bytes: u64 = 0;
var usable_pages: u64 = 0;
var allocated_pages: u64 = 0;
var next_free_hint: u64 = 0;

pub fn init(mbi_ptr: u64) void {
    // Phase 1: Scan Multiboot2 mmap to find highest address
    const parser = multiboot2.Parser.init(mbi_ptr);

    if (parser.findTag(6)) |tag_addr| {
        const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
        const entries = mmap_tag.getEntries();
        for (entries) |entry| {
            const end_addr = entry.addr + entry.len;
            if (end_addr > highest_addr) {
                highest_addr = end_addr;
            }
            if (entry.entry_type == 1) {
                total_ram_bytes += entry.len;
            }
        }
    }

    // Phase 2: Calculate bitmap size
    const addr_limit = (highest_addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    max_page = addr_limit / PAGE_SIZE;
    bitmap_size = (max_page + 7) / 8;

    // Phase 3: Find a suitable region for the bitmap itself
    var bitmap_phys: u64 = 0;
    if (parser.findTag(6)) |tag_addr| {
        const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
        const entries = mmap_tag.getEntries();
        for (entries) |entry| {
            if (entry.entry_type == 1 and entry.len >= bitmap_size) {
                const candidate = (entry.addr + entry.len - bitmap_size) & ~@as(u64, 0xFFF);
                if (candidate >= 0x200000) {
                    bitmap_phys = candidate;
                    break;
                }
            }
        }
    }

    if (bitmap_phys == 0) {
        // Fallback: use static 4GB bitmap (existing code)
    }

    bitmap_ptr = @ptrFromInt(bitmap_phys);
    @memset(bitmap_ptr[0..bitmap_size], 0xFF); // Mark all as reserved

    // Phase 4: Mark usable regions as free
    // ... (similar to existing init, but no MAX_MEM_SUPPORTED check)

    // Phase 5: Mark the bitmap itself as allocated
    // ... (prevent PMM from giving out bitmap memory)

    // Phase 6: Protect kernel, BIOS, Multiboot2 info
    // ... (same as existing)
}
```

**Ключевые изменения:**
- `bitmap` становится динамическим (`bitmap_ptr` + `bitmap_size`)
- `MAX_MEM_SUPPORTED` убирается — лимит определяется реальным объёмом RAM
- `allocPage()` / `freePage()` используют `max_page` вместо `MAX_PAGES`
- Bitmap выделяется из конца последнего usable region

**Оценка времени:** 1–2 дня

**Риски:**
- Выделение bitmap из usable region может конфликтовать с другими структурами
- Нужна защита bitmap от повторного выделения (PMM не должен отдавать свою память)
- QEMU с `-m 8G` нужен для тестирования >4GB сценариев

---

## 3. Средний приоритет (P2)

### 3.1. Сводная таблица

| Задача | Описание | Оценка сложности | Зависимости | Срок |
|--------|----------|------------------|-------------|------|
| **AHCI/SATA драйвер** | Доступ к реальным SATA дискам через PCI AHCI controller | Высокая (1–2 недели) | PCI, DMA, VFS | Недели 8–9 |
| **Higher-half kernel** | Маппинг ядра в высокие адреса (0xFFFFFFFF80000000) | Средняя (3–5 дней) | Boot64.S, linker64.ld, VMM | Недели 10–11 |
| **virtio-net + сетевой стек** | Сетевой драйвер + TCP/IP | Высокая (2–3 недели) | SMP, VFS | Недели 12–14 |
| **Per-CPU scheduler** | Полноценные per-CPU очереди вместо глобального RR | Средняя (2–3 дня) | Spinlock, atomic | Недели 3–4 |
| **TLB shootdown** | IPI + INVLPG при смене CR3 на одном CPU | Средняя (1–2 дня) | SMP, APIC IPI | Недели 5–6 |

### 3.2. AHCI/SATA драйвер

#### Архитектурные изменения

AHCI (Advanced Host Controller Interface) — стандартный интерфейс SATA-контроллеров, обнаруживаемых через PCI class 0x01 (Mass Storage), subclass 0x06 (SATA).

```
┌─────────────────────────────────────┐
│  VFS layer                         │
│  mount("/dev/sda1", "ext2")        │
├─────────────────────────────────────┤
│  Block device interface            │
│  read_block(lba, buf) / write_block│
├──────────┬──────────────────────────┤
│ AHCI     │ VirtIO-BLK              │
│ driver   │ driver (existing)       │
├──────────┴──────────────────────────┤
│  PCI bus driver (existing)         │
└─────────────────────────────────────┘
```

#### Ключевые структуры

```zig
// src64/ahci.zig

pub const HbaPort = extern struct {
    clb: u32,          // Command List Base
    clbu: u32,         // Command List Base Upper
    fb: u32,           // FIS Base
    fbu: u32,          // FIS Base Upper
    is: u32,           // Interrupt Status
    ie: u32,           // Interrupt Enable
    cmd: u32,          // Command and Status
    reserved0: u32,
    tfd: u32,          // Task File Data
    sig: u32,          // Signature
    ssts: u32,         // SATA Status
    sctl: u32,         // SATA Control
    serr: u32,         // SATA Error
    sact: u32,         // SATA Active
    ci: u32,           // Command Issue
    sntf: u32,         // SNotification
    fbs: u32,          // FIS-Based Switching Control
    reserved1: [11]u32,
    vendor: [4]u32,
};

pub const HbaMem = extern struct {
    cap: u32,          // Host Capabilities
    ghc: u32,          // Global Host Control
    is: u32,           // Interrupt Status
    pi: u32,           // Ports Implemented
    vs: u32,           // Version
    ccc_ctl: u32,      // Command Completion Coalescing Control
    ccc_pts: u32,      // CCC Ports
    em_loc: u32,       // Enclosure Management Location
    em_ctl: u32,       // EM Control
    cap2: u32,         // Extended Capabilities
    bohc: u32,         // BIOS/OS Handoff Control
    reserved: [116]u32,
    vendor: [24]u32,
    ports: [32]HbaPort,
};
```

#### Этапы реализации

1. **PCI enumeration** — сканирование bus 0 на class=0x01, subclass=0x06 (уже есть `pci.zig`)
2. **ABAR mapping** — считать BAR5 (ABAR), маппить через VMM как MMIO
3. **Port detection** — проверить `HbaMem.pi` (Ports Implemented bitmask)
4. **Port initialization** — сброс, allocate command list + FIS, enable DMA
5. **Command submission** — заполнить Command Table, установить bit в CI
6. **Read/write** — `ahci_read(port, lba, count, buf)` / `ahci_write(...)`
7. **Block device interface** — обёртка для VFS

#### Риски и mitigation

| Риск | Mitigation |
|------|-----------|
| Несовместимость с QEMU AHCI | QEMU поддерживает `-machine q35` с AHCI — тестировать в QEMU сначала |
| DMA требует identity mapping | Уже есть: virtio_blk использует identity-mapped DMA буферы |
| Прерывания от AHCI | Использовать polling сначала (как virtio_blk), добавить interrupt later |

#### Источники

- Intel AHCI Specification (rev 1.3.1)
- FreeBSD: `sys/dev/ahci/ahci.c`
- Linux: `drivers/ata/ahci.c`, `libata/`
- OSDev Wiki: https://wiki.osdev.org/AHCI

---

### 3.3. Higher-half kernel

#### Необходимые изменения

**1. Linker script (`linker64.ld`)**

```ld
/* Current: kernel at 0x100000 (identity-mapped) */
/* New: kernel at 0xFFFFFFFF80000000 (higher-half) */

ENTRY(_start)

KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;
KERNEL_PHYS_BASE = 0x100000;

SECTIONS {
    . = KERNEL_VIRT_BASE;

    .text ALIGN(4K) : AT(KERNEL_PHYS_BASE) {
        *(.text.boot64)
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : AT(KERNEL_PHYS_BASE + ADDR(.rodata) - KERNEL_VIRT_BASE) {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : AT(KERNEL_PHYS_BASE + ADDR(.data) - KERNEL_VIRT_BASE) {
        *(.data .data.*)
    }

    .bss ALIGN(4K) : AT(KERNEL_PHYS_BASE + ADDR(.bss) - KERNEL_VIRT_BASE) {
        *(.bss .bss.*)
        *(COMMON)
    }

    _kernel_end = .;
}
```

**2. Boot assembly (`boot64.S`)**

Ранний загрузочный код (до включения paging) работает с физическими адресами. После загрузки CR3 и включения paging, делаем `jmp` на виртуальный адрес:

```asm
# After enabling paging (CR0.PG = 1):
    # We're still executing at physical address (identity-mapped)
    # Jump to higher-half virtual address
    movabs $higher_half_entry, rax
    jmp *rax

higher_half_entry:
    # Now running at 0xFFFFFFFF80XXXXX
    # Load GDT64 with virtual base address
    lgdt [gdt64.pointer_virt]
```

**3. Page tables (`boot64.S`)**

Необходимо создать **два** маппинга:
- Identity-mapped: `0x100000 → 0x100000` (для раннего boot кода)
- Higher-half: `0xFFFFFFFF80000000 → 0x100000` (для основного ядра)

**4. VMM (`vmm64.zig`)**

Все функции VMM должны работать с виртуальными адресами. `pml4_phys` остаётся физическим, но все обращения через `@ptrFromInt()` используют виртуальные адреса.

**Риски:**

| Риск | Mitigation |
|------|-----------|
| Ранний boot код ломается | Identity-mapping сохраняется до завершения перехода |
| GDT/IDT указывают на физические адреса | Обновить GDT base на виртуальный адрес после перехода |
| DMA требует физических адресов | Ядро уже знает phys=virt-offset, добавляется макрос `V2P` / `P2V` |
| Отладка через GDB сложнее | GDB понимает виртуальные адреса |

**Оценка времени:** 3–5 дней

---

### 3.4. virtio-net + сетевой стек

#### Архитектура

```
┌─────────────────────────────────────┐
│  Application layer                  │
│  socket(), connect(), send(), recv()│
├─────────────────────────────────────┤
│  TCP/UDP transport                  │
├─────────────────────────────────────┤
│  IPv4/IPv6 network layer            │
├─────────────────────────────────────┤
│  Ethernet data link layer           │
├──────────┬──────────────────────────┤
│virtio-net│ e1000                    │
│ (QEMU)   │ (real HW)               │
├──────────┴──────────────────────────┤
│  PCI bus driver                     │
└─────────────────────────────────────┘
```

#### Этапы реализации

1. **virtio-net драйвер** (аналог virtio_blk)
   - PCI enumeration (device ID 0x1000, vendor 0x1AF4)
   - Receive + transmit virtqueues
   - MAC address из PCI config space
   - Packet buffer allocation

2. **Ethernet frame parser**
   - MAC address matching
   - ARP request/reply
   - Frame CRC verification (optional)

3. **IPv4 layer**
   - IP header parsing
   - ICMP echo reply (ping)
   - IP fragmentation/reassembly

4. **UDP/TCP** (фазы)
   - UDP: simple datagram send/receive
   - TCP: state machine (SYN, SYN-ACK, ACK, FIN)

5. **Socket interface** (интеграция с VFS)
   - `socket()`, `bind()`, `listen()`, `accept()`, `connect()`
   - Socket as VFS file descriptor

#### Риски и mitigation

| Риск | Mitigation |
|------|-----------|
| Сложность TCP state machine | Начать с UDP + ICMP ping, добавить TCP позже |
| Прерывания от virtio-net | Использовать polling сначала, interrupt later |
| Буферизация пакетов | Выделять из PMM, ограничить max packet size |

---

### 3.5. Per-CPU scheduler

**Подробности в разделе P0 (1.3)** — это технически P1/P2, но блокирует компиляцию с SMP, поэтому обработано выше.

---

### 3.6. TLB shootdown

#### Проблема

Когда один CPU меняет CR3 (context switch) или модифицирует page table entry, другие CPU могут иметь устаревшие TLB-записи. На x86_64 запись в CR3 flushes TLB на локальном CPU, но **не** на других.

#### Решение

```zig
// src64/tlb.zig

const smp = @import("smp.zig");
const hal = @import("hal.zig");
const atomic = @import("atomic.zig");

/// TLB shootdown vector (IPI vector for INVLPG broadcast)
const TLB_SHOOTDOWN_VECTOR: u32 = 0x31;

/// Pending shootdown request
pub const ShootdownRequest = struct {
    virt_addr: u64,
    page_count: u64,
    ack_bitmap: AtomicU32,
};

var pending_request: ShootdownRequest = undefined;
var request_ready: AtomicFlag = .{};

/// Request a TLB shootdown on all other CPUs.
pub fn requestShootdown(virt_addr: u64, page_count: u64) void {
    pending_request.virt_addr = virt_addr;
    pending_request.page_count = page_count;
    pending_request.ack_bitmap.set(1 << smp.currentCpuId());

    request_ready.trySet();

    const my_id = smp.currentCpuId();
    for (0..smp.online_cpus) |i| {
        if (i != my_id) {
            hal.APIC.sendIpi(smp.cpu_data[i].lapic_id, TLB_SHOOTDOWN_VECTOR);
        }
    }

    // Local INVLPG
    var i: u64 = 0;
    while (i < page_count) : (i += 1) {
        asm volatile ("invlpg (%[virt])"
            :
            : [virt] "r" (virt_addr + i * 4096),
            : "memory"
        );
    }

    // Wait for all ACKs
    var timeout: u32 = 0;
    const all_mask: u32 = (1 << smp.online_cpus) - 1;
    while (pending_request.ack_bitmap.get() != all_mask and timeout < 1000000) : (timeout += 1) {
        asm volatile ("pause");
    }
}

/// Called from ISR when this CPU receives a TLB shootdown IPI.
pub fn handleShootdownIpi() void {
    if (!request_ready.isSet()) return;

    var i: u64 = 0;
    while (i < pending_request.page_count) : (i += 1) {
        asm volatile ("invlpg (%[virt])"
            :
            : [virt] "r" (pending_request.virt_addr + i * 4096),
            : "memory"
        );
    }

    _ = pending_request.ack_bitmap.add(1 << smp.currentCpuId());
}
```

**Интеграция:** ISR vector 0x31 в `isr64.S` → `hal.zig` → `tlb.handleShootdownIpi()`.

**Оценка времени:** 1–2 дня

---

## 4. Общий график и милстоуны

### 4.1. Диаграмма (текстовый Гант)

```
Неделя 1-2:  P0 — Создание spinlock.zig + atomic.zig + CpuRunQueue
             ├── Инженер A: spinlock.zig + atomic.zig (4-6 часов)
             ├── Инженер B: CpuRunQueue в scheduler.zig (8-16 часов)
             └── Параллельно: очистка legacy (2 часа)

Неделя 3-4:  P0 — SMP тестирование в QEMU
             ├── QEMU -smp 2: базовая загрузка (4 часа)
             ├── Отладка triple faults (8-16 часов, резерв)
             ├── TLB shootdown реализация (1-2 дня)
             └── Per-CPU scheduler интеграция (2-3 дня)

             МИЛСТОУН 1: Ядро загружается с -smp 2, оба CPU работают
                 Критерий: online_cpus == 2, нет triple fault, 1 час stress test

Неделя 5-6:  P1 — PMM >4GB + VFS дизайн
             ├── Инженер A: PMM динамический bitmap (1-2 дня)
             ├── Инженер B: VFS интерфейс + inode + mount table (1-2 недели)
             └── Интеграция FAT32 через VfsOps (2-3 дня)

             МИЛСТОУН 2: VFS с FAT32 бэкендом
                 Критерий: mount("/dev/vda1", "fat32") + open/read/write/close

Неделя 7-8:  P1 — VFS интеграция + AHCI начало
             ├── VFS path resolution + per-process namespace (3-5 дней)
             ├── AHCI PCI enumeration + ABAR mapping (2-3 дня)
             └── AHCI port init + read/write (5-7 дней)

Неделя 9-10: P2 — Higher-half kernel
             ├── Linker script update (1 день)
             ├── boot64.S dual mapping (1-2 дня)
             ├── GDT/IDT virtual addresses (1 день)
             └── VMM адаптация + тестирование (1-2 дня)

             МИЛСТОУН 3: Higher-half kernel + AHCI
                 Критерий: ядро работает на виртуальных адресах,
                           SATA диск доступен через VFS

Неделя 11-14: P2 — Сетевой стек
             ├── virtio-net драйвер (5-7 дней)
             ├── Ethernet + ARP (2-3 дня)
             ├── IPv4 + ICMP ping (3-4 дня)
             ├── UDP (2-3 дня)
             └── TCP (5-7 дней, опционально)

             МИЛСТОУН 4: Сетевой стек + ping
                 Критерий: QEMU ping проходит, UDP echo работает
```

### 4.2. Критический путь

```
spinlock.zig + atomic.zig → CpuRunQueue → SMP QEMU test → Per-CPU scheduler
                                                                    ↓
                                                              VFS дизайн
                                                                    ↓
                                                              VFS + FAT32
                                                                    ↓
                                                              AHCI/SATA
                                                                    ↓
                                                              Higher-half
                                                                    ↓
                                                              virtio-net
                                                                    ↓
                                                              Network stack
```

### 4.3. Распределение задач (1-3 инженера)

| Роль | Недели 1-4 | Недели 5-8 | Недели 9-14 |
|------|------------|------------|-------------|
| **Инженер A** (kernel/core) | spinlock, atomic, CpuRunQueue, SMP test | PMM >4GB, VFS core | Higher-half, TLB |
| **Инженер B** (drivers/FS) | Очистка legacy, SMP debug assist | VFS FAT32 adapter, AHCI | virtio-net, network |
| **Инженер C** (testing/CI) | CI/CD setup, QEMU scripts, stress test | VFS tests, AHCI tests | Network tests |

---

## 5. Рекомендации по инструментам и CI/CD

### 5.1. GitHub Actions

```yaml
# .github/workflows/kernel-ci.yml
name: POLER-OS Kernel CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Zig 0.13.0
        run: |
          wget -q https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz
          tar xf zig-linux-x86_64-0.13.0.tar.xz
          echo "$PWD/zig-linux-x86_64-0.13.0" >> $GITHUB_PATH

      - name: Build kernel
        working-directory: zig-kernel
        run: zig build -Doptimize=ReleaseSmall

      - name: Run unit tests
        working-directory: zig-kernel
        run: zig build test

  smp-test:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4

      - name: Install QEMU + dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y qemu-system-x86 grub-pc-bin xorriso

      - name: Build ISO
        working-directory: zig-kernel
        run: |
          zig build -Doptimize=ReleaseSmall
          bash build-iso.sh

      - name: Test SMP boot (2 CPUs)
        timeout-minutes: 2
        run: |
          timeout 30 qemu-system-x86_64 \
            -cdrom zig-kernel/poler-os64.iso \
            -m 256M -smp 2 \
            -serial stdio -display none -no-reboot \
            2>&1 | tee /tmp/smp-output.log
          grep -q "All CPUs online: 2" /tmp/smp-output.log || exit 1

      - name: Test single CPU boot
        timeout-minutes: 2
        run: |
          timeout 30 qemu-system-x86_64 \
            -cdrom zig-kernel/poler-os64.iso \
            -m 256M -smp 1 \
            -serial stdio -display none -no-reboot \
            2>&1 | tee /tmp/single-output.log
          grep -q "POLER-OS" /tmp/single-output.log || exit 1
```

### 5.2. Юнит-тесты новых модулей

```bash
# Запуск тестов для новых модулей (target = host x86_64 Linux)
zig test zig-kernel/src64/spinlock.zig
zig test zig-kernel/src64/atomic.zig

# Запуск всех тестов ядра
zig build test
```

### 5.3. QEMU отладка

```bash
# Режим отладки: логирование guest errors и прерываний
qemu-system-x86_64 \
    -cdrom poler-os64.iso \
    -m 256M -smp 2 \
    -serial stdio -display none -no-reboot \
    -d guest_errors,int,cpu_reset \
    -D /tmp/qemu-debug.log

# GDB remote debug
qemu-system-x86_64 ... -s -S  # Ожидать GDB подключение
gdb -ex "target remote :1234" -ex "break poler_kernel_main"

# Дамп состояния CPU при triple fault
qemu-system-x86_64 ... -d int,cpu_reset 2>&1 | rg "Triple fault"
```

### 5.4. Логирование и дамп при панике

Рекомендуется добавить в `hal.zig` функцию `kernelPanic()`, которая:

1. Отключает прерывания (`cli`)
2. Выводит в Serial: panic message, RIP, RSP, CR3, CS
3. Выводит stack trace (обход RBP цепочки)
4. Останавливает все CPU через IPI
5. Входит в бесконечный `hlt` цикл

```zig
pub fn kernelPanic(msg: []const u8, frame: *const InterruptFrame) noreturn {
    cli();
    Serial.puts("\n!!! KERNEL PANIC !!!\n");
    Serial.puts("Message: ");
    Serial.puts(msg);
    Serial.puts("\nRIP=0x");
    Serial.putHex(frame.rip);
    Serial.puts(" CS=0x");
    Serial.putHex(frame.cs);
    Serial.puts(" RSP=0x");
    Serial.putHex(frame.rsp);
    Serial.puts(" CR3=0x");
    Serial.putHex(readCr3());
    Serial.puts("\n");

    // Stack trace (RBP chain)
    var rbp: u64 = frame.rbp;
    var depth: usize = 0;
    while (rbp != 0 and depth < 16) : (depth += 1) {
        const ret_addr: *const u64 = @ptrFromInt(rbp + 8);
        Serial.puts("  #");
        Serial.putDecimal(depth);
        Serial.puts(" 0x");
        Serial.putHex(ret_addr.*);
        Serial.puts("\n");
        rbp = @as(*const u64, @ptrFromInt(rbp)).*;
    }

    // Halt all CPUs
    // TODO: send IPI to all other CPUs

    while (true) {
        hlt();
    }
}
```

---

## 6. Открытые вопросы

1. **Переключение на MLFQ scheduler:** ROADMAP описывает Round-Robin. Когда переходить на Multi-Level Feedback Queue? Рекомендация: после стабилизации SMP (v0.8.0), в v0.9.0.

2. **Формат бинарников для user-space:** ELF-only или PE/COFF тоже? Shim-архитектура описывает оба, но ELF loader уже есть. Рекомендация: ELF-first, PE после VFS.

3. **VFS: поддерживать ли initrd как файловую систему?** CPIO parser уже есть. Рекомендация: реализовать `cpio_vfs_ops` как read-only FS для /initrd.

4. **Higher-half: какой виртуальный адрес?** Предлагается `0xFFFFFFFF80000000` (как в Linux). Альтернатива: `0xFFFF800000000000` (канонический high, оставляет место для mmap). Требует решения архитектурного совета.

5. **Сетевой стек: свой или lwIP?** Написание своего TCP/IP стека — 2-3 недели. Порт lwIP — 1-2 недели, но добавляет зависимость. Рекомендация: свой стек для простых случаев (ICMP/UDP), рассмотреть lwIP для TCP.

6. **SMP: максимальное количество CPU.** Сейчас `MAX_CPUS = 8`. Для серверных сценариев нужно 64+. Когда увеличивать? Рекомендация: после v0.8.0, когда SMP стабилизирован.

7. **Динамический PMM bitmap: где размещать?** Предлагается конец последнего usable region. Но что если bitmap пересекается с ACPI NVS или reserved region? Нужен более надёжный алгоритм поиска.

8. **Стабильность Playground:** Playground (Next.js) не в git и не в scope этого плана, но его стабильность влияет на рабочий процесс. Рекомендация: перенести в отдельный репозиторий или заменить на AI API в будущем.

---

*Microsoft не диктует правила. Правила диктует архитектура.*
