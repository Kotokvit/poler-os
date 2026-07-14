# POLER-OS

**x86_64 монолитное антивирусное ядро на Zig 0.13.0**

Загрузка через Multiboot2/GRUB в 64-bit long mode. Ядро спроектировано как anti-cheat/anti-malware платформа: APIC ISR хэширует ввод, CR3/PML4 страницы хэшируются, PND подписывает переходы потока управления. Читы и вредоносный код физически не могут существовать в этой архитектуре.

---

## Текущая версия: v0.7.0

| Подсистема | Статус | Описание |
|---|---|---|
| Boot | ✅ | Multiboot2 → 32→64 transition → identity paging (4GB, 2MB pages) |
| HAL | ✅ | GDT, IDT, PIC remap, Local APIC timer (vector 48), IO-APIC, TSS IST1 |
| ACPI | ✅ | RSDP/RSDT/MADT/HPET parsing |
| Memory | ✅ | PMM (bitmap), VMM (4-level paging + OOM rollback), kernel heap (free-list + SipHash-2-4) |
| Scheduler | ✅ | Round-robin с APIC timer preemption (8 задач, divisor 16) |
| Ring 3 | ✅ | User mode: ELF64 loader, per-process CR3, syscall/sysretq, TSS IST |
| Framebuffer | ✅ | Linear framebuffer (1024×768×32bpp) + bitmap font |
| Keyboard | ✅ | PS/2 Set 2 → Set 1 translation через i8042 controller |
| Serial | ✅ | COM1 (115200 baud, 8N1) |
| Crypto | ✅ | PND v8 (Parametric Nonlinear Diffusion), RSA-OAEP + POLER-CTR AEAD |
| Syscalls | ✅ | syscall/sysretq: print, read_key, clear_screen |
| SMP | ❌ | Планируется |
| Networking | ❌ | Планируется (virtio-net) |

---

## Сборка

### Зависимости

- Zig 0.13.0
- QEMU (для тестирования)
- GRUB (`grub-pc-bin`, `grub-mkrescue`)
- `xorriso`

### Команды

```bash
# Сборка ядра (32-bit + 64-bit)
zig build

# Сборка загрузочного ISO
cd zig-kernel && bash build-iso.sh

# Запуск 64-bit ядра в QEMU (direct kernel boot)
zig build run64

# Запуск 32-bit ядра в QEMU
zig build run32

# Тесты POLER Core + RSA-OAEP
zig build test
```

### Запуск ISO в QEMU

```bash
qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio -no-reboot
```

---

## Структура проекта

```
zig-kernel/
├── src64/                    # 64-bit ядро (POLER-OS v0.7.0)
│   ├── boot64.S              # Multiboot2 header, 32→64 переход, page tables
│   ├── isr64.S               # ISR/IRQ stubs + syscall entry
│   ├── main64.zig            # Точка входа, boot sequence, shell
│   ├── hal.zig               # HAL: GDT/IDT/PIC/APIC/IOAPIC/keyboard/serial
│   ├── acpi.zig              # RSDP/RSDT/MADT/HPET парсинг
│   ├── pmm64.zig             # Physical Memory Manager (bitmap)
│   ├── vmm64.zig             # Virtual Memory Manager (4-level paging)
│   ├── heap64.zig            # Kernel heap (free-list + SipHash-2-4)
│   ├── scheduler.zig         # Round-robin scheduler (APIC preempt)
│   ├── elf_loader.zig        # ELF64 loader (Ring 3 user mode)
│   ├── framebuffer.zig       # Linear framebuffer + bitmap font
│   ├── multiboot2.zig        # Multiboot2 info parser
│   ├── cpio.zig              # CPIO initrd parser
│   ├── poler_core.zig        # PND v8 tensor algebra
│   ├── rsa_oaep.zig          # RSA-OAEP + POLER-CTR AEAD
│   └── linker64.ld           # Linker script
├── src/                      # Legacy 32-bit ядро
│   ├── boot32.S              # 16-bit real → 32-bit protected mode
│   ├── isr32.S               # 32-bit ISR stubs
│   ├── main32.zig            # 32-bit kernel entry
│   └── ...
├── drivers/                  # Общие драйверы
├── arch/                     # Архитектурно-зависимый код
├── boot/                     # Boot logic
├── mm/                       # Memory management helpers
├── iso/                      # GRUB ISO структура (BIOS boot)
├── iso-efi/                  # GRUB ISO структура (UEFI boot)
├── iso-minimal/              # Минимальная ISO структура
├── build.zig                 # Конфигурация сборки Zig
├── build-iso.sh              # Скрипт сборки ISO
└── run-qemu.sh               # Скрипт запуска QEMU
```

---

## Дорожная карта

- [x] Загрузка в 64-bit long mode
- [x] HAL (GDT/IDT/PIC/APIC)
- [x] APIC timer на vector 48
- [x] Собственный GDT + TSS
- [x] PMM + VMM + kernel heap
- [x] Round-robin scheduler
- [x] POLER Core (PND v8, RSA-OAEP, POLER-CTR)
- [x] Syscalls (syscall/sysretq)
- [x] Ring 3 (user mode) + ELF64 loader + per-process CR3
- [ ] SMP (многоядерность)
- [ ] Networking (virtio-net)
- [ ] Anti-cheat gaming platform

---

## История версий

### v0.7.0 — Ring 3 User Mode
- ELF64 loader, per-process CR3, TSS IST1
- User code/data segments (CS=0x1B, SS=0x23)
- syscall/sysretq privilege switch
- IRETQ для возврата в user mode

### v0.6.1 — Bug Fixes
- CTR brace mismatch в hybridEncrypt()
- Q glyph рендеринг
- Circular import hal↔scheduler → callback

### v0.6.0 — Preemptive Multitasking
- Round-robin scheduler с APIC timer
- 8 одновременных задач
- Context switch через stack-based состояния

### v0.5.0 — 64-bit Long Mode
- Multiboot2 boot, 32→64 переход
- HAL: GDT, IDT, PIC, APIC
- PMM + VMM + kernel heap

---

## Лицензия

GNU General Public License v3.0 or later (GPLv3+). См. [LICENSE](LICENSE).
