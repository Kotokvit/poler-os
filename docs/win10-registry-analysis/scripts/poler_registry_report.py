#!/usr/bin/env python3
"""
POLER-OS: Windows 10 Registry Deep Analysis Report
Generates a PDF report with all registry analysis results.
"""

import os
import json
import hashlib
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    KeepTogether, HRFlowable
)

# ━━ Cascade Palette ━━
PAGE_BG       = colors.HexColor('#f4f3f3')
SECTION_BG    = colors.HexColor('#ececeb')
CARD_BG       = colors.HexColor('#ebeae6')
TABLE_STRIPE  = colors.HexColor('#ecebe8')
HEADER_FILL   = colors.HexColor('#564f37')
COVER_BLOCK   = colors.HexColor('#595443')
BORDER        = colors.HexColor('#c1bdb1')
ICON          = colors.HexColor('#756945')
ACCENT        = colors.HexColor('#95771c')
ACCENT_2      = colors.HexColor('#6f54bd')
TEXT_PRIMARY   = colors.HexColor('#171715')
TEXT_MUTED     = colors.HexColor('#8e8c85')
SEM_SUCCESS   = colors.HexColor('#4e9566')
SEM_WARNING   = colors.HexColor('#8e7749')
SEM_ERROR     = colors.HexColor('#a4564f')
SEM_INFO      = colors.HexColor('#517ba5')

OUTPUT_DIR = "/home/z/my-project/download"
RESULTS_DIR = "/home/z/my-project/registry-analysis/results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ━━ Styles ━━
styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    'CustomTitle', parent=styles['Title'],
    fontSize=22, leading=26, textColor=HEADER_FILL,
    spaceAfter=6, fontName='Helvetica-Bold'
)
h1_style = ParagraphStyle(
    'H1', parent=styles['Heading1'],
    fontSize=16, leading=20, textColor=HEADER_FILL,
    spaceBefore=18, spaceAfter=8, fontName='Helvetica-Bold'
)
h2_style = ParagraphStyle(
    'H2', parent=styles['Heading2'],
    fontSize=13, leading=16, textColor=ACCENT,
    spaceBefore=12, spaceAfter=6, fontName='Helvetica-Bold'
)
h3_style = ParagraphStyle(
    'H3', parent=styles['Heading3'],
    fontSize=11, leading=14, textColor=ICON,
    spaceBefore=8, spaceAfter=4, fontName='Helvetica-Bold'
)
body_style = ParagraphStyle(
    'CustomBody', parent=styles['Normal'],
    fontSize=9.5, leading=13, textColor=TEXT_PRIMARY,
    alignment=TA_JUSTIFY, spaceAfter=4,
    fontName='Helvetica'
)
code_style = ParagraphStyle(
    'Code', parent=styles['Normal'],
    fontSize=8, leading=10, textColor=ACCENT_2,
    fontName='Courier', backColor=colors.HexColor('#f0efed'),
    leftIndent=8, spaceAfter=4, spaceBefore=2
)
muted_style = ParagraphStyle(
    'Muted', parent=styles['Normal'],
    fontSize=8.5, leading=11, textColor=TEXT_MUTED,
    fontName='Helvetica'
)
table_header_style = ParagraphStyle(
    'TH', fontSize=8.5, leading=10, textColor=colors.white,
    fontName='Helvetica-Bold', alignment=TA_CENTER
)
table_cell_style = ParagraphStyle(
    'TC', fontSize=8, leading=10, textColor=TEXT_PRIMARY,
    fontName='Helvetica'
)
table_cell_code = ParagraphStyle(
    'TCC', fontSize=7.5, leading=9.5, textColor=ACCENT_2,
    fontName='Courier'
)


def make_table(headers, rows, col_widths=None):
    """Create a styled table"""
    available = A4[0] - 60  # 30mm margins each side
    if not col_widths:
        col_widths = [available / len(headers)] * len(headers)
    
    header_cells = [Paragraph(h, table_header_style) for h in headers]
    data = [header_cells]
    for row in rows:
        data.append([Paragraph(str(c), table_cell_style) for c in row])
    
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), HEADER_FILL),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, 0), 8.5),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 1), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), TABLE_STRIPE))
    t.setStyle(TableStyle(style_cmds))
    return t


def load_json(filename):
    """Load analysis result JSON"""
    path = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}


def build_report():
    output_path = os.path.join(OUTPUT_DIR, "POLER-OS_Win10_Registry_Analysis.pdf")
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=30, rightMargin=30,
        topMargin=25, bottomMargin=20,
        backgroundColor=PAGE_BG
    )
    
    story = []
    
    # ════════════════════════════════════════
    # COVER
    # ════════════════════════════════════════
    story.append(Spacer(1, 60))
    story.append(Paragraph("POLER-OS", ParagraphStyle(
        'CoverTitle', fontSize=36, leading=42, textColor=HEADER_FILL,
        fontName='Helvetica-Bold', alignment=TA_CENTER
    )))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Windows 10 Registry Deep Analysis", ParagraphStyle(
        'CoverSub', fontSize=18, leading=22, textColor=ACCENT,
        fontName='Helvetica', alignment=TA_CENTER
    )))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="60%", thickness=2, color=ACCENT, spaceAfter=12, spaceBefore=8))
    story.append(Paragraph("Source: Windows 10 22H2 English x64 (Build 19045.2965)", ParagraphStyle(
        'CoverInfo', fontSize=11, leading=14, textColor=TEXT_MUTED,
        fontName='Helvetica', alignment=TA_CENTER
    )))
    story.append(Paragraph("Hive Files: SYSTEM, SOFTWARE, COMPONENTS, DEFAULT, SAM, SECURITY", ParagraphStyle(
        'CoverInfo2', fontSize=10, leading=13, textColor=TEXT_MUTED,
        fontName='Helvetica', alignment=TA_CENTER
    )))
    story.append(Spacer(1, 30))
    story.append(Paragraph("Purpose: Extract and analyze Windows registry structure for POLER-OS NT API compatibility layer implementation", ParagraphStyle(
        'CoverPurpose', fontSize=10, leading=14, textColor=TEXT_PRIMARY,
        fontName='Helvetica', alignment=TA_CENTER
    )))
    story.append(Spacer(1, 40))
    story.append(Paragraph("2026-07-18", ParagraphStyle(
        'CoverDate', fontSize=10, textColor=TEXT_MUTED,
        fontName='Helvetica', alignment=TA_CENTER
    )))
    story.append(PageBreak())
    
    # ════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(Paragraph(
        "This document presents the results of a deep analysis of the Windows 10 22H2 (Build 19045.2965) registry, "
        "extracted directly from the distribution WIM image without installing the operating system. The analysis covers "
        "the critical registry hives (SYSTEM, SOFTWARE, COMPONENTS) and extracts structural data essential for implementing "
        "the NT API compatibility layer in POLER-OS. The analysis reveals 473 NtXxx system calls that must be implemented, "
        "29 KnownDLLs that must be force-loaded, 93 boot drivers that initialize hardware, and the complete API Set mapping "
        "architecture that Windows uses to redirect API calls from virtual api-ms-win-* DLL names to real implementation DLLs. "
        "Additionally, the Win32 subsystem registration (csrss.exe + win32k.sys), the service group boot order with 72 ordered "
        "groups, and the cryptography provider architecture are documented in detail. This data provides the foundation for "
        "POLER-OS to achieve Win32 compatibility at a level deeper than Wine and ReactOS, by directly implementing the "
        "registry-driven configuration that Windows itself uses rather than reverse-engineering behavioral patterns.",
        body_style
    ))
    
    # Key metrics table
    story.append(Spacer(1, 6))
    story.append(Paragraph("Key Metrics", h3_style))
    metrics = [
        ["NtXxx System Calls", "473", "Core NT syscall table"],
        ["ZwXxx Kernel Calls", "472", "Kernel-mode syscall mirrors"],
        ["Nt/Zw Pairs", "472", "Near 1:1 correspondence"],
        ["RtlXxx Runtime Functions", "994", "Runtime library helpers"],
        ["KnownDLLs", "29", "Force-loaded system DLLs"],
        ["Boot Drivers (Start=0)", "93", "Hardware initialization"],
        ["System Drivers (Start=1)", "29", "IO subsystem init"],
        ["Total Services/Drivers", "663", "Complete driver ecosystem"],
        ["API Set Categories", "7", "api-ms-win-core, -crt, -service..."],
        ["API Set DLLs (api-ms-win-*)", "91", "Virtual DLL redirections"],
        ["System32 DLLs Total", "3,105", "Complete DLL inventory"],
        ["Device Class GUIDs", "110", "Hardware class categories"],
        ["Service Boot Groups", "72", "Ordered initialization sequence"],
        ["CSP Crypto Providers", "10", "Cryptographic Service Providers"],
        ["IFEO Entries", "23", "Process interception points"],
    ]
    story.append(make_table(["Metric", "Value", "Notes"], metrics, [120, 60, 280]))
    
    # ════════════════════════════════════════
    # 2. API SET MAPPING
    # ════════════════════════════════════════
    story.append(Paragraph("2. API Set Mapping Architecture", h1_style))
    story.append(Paragraph(
        "The API Set mechanism is one of the most critical architectural features that POLER-OS must implement correctly. "
        "Starting with Windows 7, Microsoft introduced API Sets as a way to decouple API contracts from implementation DLLs. "
        "Instead of applications linking directly to kernel32.dll or advapi32.dll, they link to virtual DLLs with names like "
        "api-ms-win-core-file-l1-2-0.dll. The OS then resolves these virtual names to actual implementation DLLs at load time. "
        "This indirection layer allows Microsoft to reorganize internal DLL structure without breaking application compatibility. "
        "For POLER-OS, implementing this mapping correctly is essential because modern Windows applications and anti-cheat systems "
        "expect this redirection mechanism to function properly.",
        body_style
    ))
    
    story.append(Paragraph("2.1 API Set Resolution Mechanism", h2_style))
    story.append(Paragraph(
        "The API Set map is NOT stored directly in the offline registry. The key HKLM\\SYSTEM\\CurrentControlSet\\Control\\ApiSetMap "
        "exists only at runtime and is populated by the kernel from apisetchema.dll during boot. However, the registry does contain "
        "ApiSetSchemaExtensions under Session Manager, which adds extensions to the base schema. The actual API Set resolution works "
        "through a binary structure inside apisetchema.dll that maps each virtual DLL name prefix to a list of candidate implementation "
        "DLLs, with the first valid candidate being selected. In our analysis of the offline WIM image, we found 91 api-ms-win-* DLL "
        "files in the System32 directory and additional API set extension data in the Session Manager registry key. The Win10 22H2 "
        "distribution uses API Set schema version 6, which supports both api-ms-win-* and ext-ms-win-* namespace prefixes.",
        body_style
    ))
    
    # API Set categories
    story.append(Paragraph("2.2 API Set Categories", h2_style))
    apiset_data = load_json("apiset_dlls_analysis.json")
    categories = apiset_data.get("summary", {}).get("categories", {})
    cat_rows = [[cat, str(count)] for cat, count in sorted(categories.items(), key=lambda x: -x[1])]
    story.append(make_table(["Category", "DLL Count"], cat_rows, [350, 110]))
    
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The api-ms-win-core category dominates with 63 DLLs, covering file I/O, memory management, process/thread operations, "
        "synchronization, registry access, and other fundamental operations. This is the primary target for POLER-OS implementation. "
        "The api-ms-win-crt category (15 DLLs) covers the C runtime, which maps primarily to ucrtbase.dll. The api-ms-win-service "
        "category (7 DLLs) covers service control manager operations. For POLER-OS, implementing the core category first provides "
        "the foundation for running most applications, while the security and service categories are critical for anti-cheat compatibility.",
        body_style
    ))
    
    # Full API Set DLL list
    story.append(Paragraph("2.3 Complete API Set DLL Inventory", h2_style))
    api_dlls = apiset_data.get("api_ms_win", [])
    # Split into columns
    dll_rows = []
    for i in range(0, len(api_dlls), 3):
        row = api_dlls[i:i+3]
        while len(row) < 3:
            row.append("")
        dll_rows.append(row)
    if dll_rows:
        avail = A4[0] - 60
        story.append(make_table(["DLL 1", "DLL 2", "DLL 3"], dll_rows, [avail/3]*3))
    
    # ════════════════════════════════════════
    # 3. KNOWN DLLs
    # ════════════════════════════════════════
    story.append(Paragraph("3. KnownDLLs System", h1_style))
    story.append(Paragraph(
        "KnownDLLs is a security mechanism that forces certain system DLLs to always be loaded from the System32 directory, "
        "preventing DLL search order hijacking attacks. When the loader encounters a DLL name that is in the KnownDLLs list, "
        "it ignores the application's DLL search path and loads directly from the system directory. This is critical for "
        "anti-cheat systems and game integrity, as it prevents attackers from placing malicious versions of system DLLs in "
        "application directories. The Session Manager (smss.exe) creates the KnownDLLs object directory during boot, mapping "
        "each DLL name to its memory-mapped section. For POLER-OS, this mechanism must be replicated exactly: the kernel must "
        "maintain the KnownDLLs object directory and the loader must check it before searching the normal DLL path.",
        body_style
    ))
    
    kd = load_json("knowndlls_detail.json")
    kd_rows = []
    for k, v in sorted(kd.items()):
        if not k.startswith("_") and isinstance(v, dict):
            kd_rows.append([k, v.get("value", ""), v.get("type", "")])
    story.append(make_table(["Internal Name", "DLL File", "Type"], kd_rows, [100, 150, 210]))
    
    # ════════════════════════════════════════
    # 4. NT SYSCALL TABLE
    # ════════════════════════════════════════
    story.append(Paragraph("4. NT System Call Table (ntdll.dll)", h1_style))
    story.append(Paragraph(
        "The ntdll.dll export table is the definitive interface between user-mode applications and the NT kernel. Every Win32 "
        "API call eventually resolves to one or more NtXxx functions in ntdll.dll, which transition to kernel mode via the "
        "syscall instruction. The ZwXxx functions are identical to NtXxx but are intended for kernel-mode callers - they skip "
        "the previous-mode check that NtXxx performs. In Win10 22H2, ntdll.dll exports 473 NtXxx functions and 472 ZwXxx "
        "functions, with 472 Nt/Zw pairs. This near-perfect pairing means that POLER-OS must implement a syscall table with "
        "approximately 473 entries. Additionally, there are 994 RtlXxx runtime library functions that provide user-mode "
        "utilities like string manipulation, security descriptor operations, and memory management. These Rtl functions do NOT "
        "transition to kernel mode - they are pure user-mode code that POLER-OS must implement in its ntdll compatibility layer.",
        body_style
    ))
    
    story.append(Paragraph("4.1 Syscall Classification", h2_style))
    nt_data = load_json("ntdll_analysis.json")
    nt_funcs = nt_data.get("nt_functions", [])
    
    # Classify by functional area
    classifications = {
        "Process/Thread": [f for f in nt_funcs if any(x in f for x in ["Process", "Thread"])],
        "Memory/VM": [f for f in nt_funcs if any(x in f for x in ["VirtualMemory", "Memory", "Section", "Protect"])],
        "File/IO": [f for f in nt_funcs if any(x in f for x in ["File", "IoCompletion", "DeviceIoControl"])],
        "Registry": [f for f in nt_funcs if "Key" in f or "Registry" in f],
        "Security/Token": [f for f in nt_funcs if any(x in f for x in ["Token", "Security", "AccessCheck", "Privilege"])],
        "Synchronization": [f for f in nt_funcs if any(x in f for x in ["Event", "Semaphore", "Mutant", "Timer", "Wait"])],
        "IPC/Port": [f for f in nt_funcs if any(x in f for x in ["Port", "Alpc", "Mailslot", "NamedPipe"])],
        "Object Manager": [f for f in nt_funcs if any(x in f for x in ["Object", "Directory", "SymbolicLink"])],
        "Transaction/TM": [f for f in nt_funcs if any(x in f for x in ["Transaction", "Enlistment", "ResourceManager"])],
        "Other": [f for f in nt_funcs if not any(x in f for x in [
            "Process", "Thread", "VirtualMemory", "Memory", "Section", "Protect",
            "File", "IoCompletion", "DeviceIoControl", "Key", "Registry",
            "Token", "Security", "AccessCheck", "Privilege",
            "Event", "Semaphore", "Mutant", "Timer", "Wait",
            "Port", "Alpc", "Mailslot", "NamedPipe",
            "Object", "Directory", "SymbolicLink",
            "Transaction", "Enlistment", "ResourceManager"
        ])]
    }
    
    class_rows = [[name, str(len(funcs)), ", ".join(funcs[:5]) + ("..." if len(funcs) > 5 else "")]
                   for name, funcs in sorted(classifications.items(), key=lambda x: -len(x[1]))]
    story.append(make_table(["Category", "Count", "Examples"], class_rows, [100, 50, 310]))
    
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The largest category is Process/Thread operations, which includes process creation (NtCreateProcess, NtCreateUserProcess), "
        "thread management (NtCreateThreadEx, NtSetInformationThread), and job object control. This is the primary attack surface "
        "for anti-cheat systems, which monitor process and thread creation through kernel callbacks. The File/IO category covers "
        "all file operations that POLER-FS must support, including NtCreateFile, NtReadFile, NtWriteFile, and NtDeviceIoControlFile. "
        "The IPC/Port category includes ALPC (Advanced Local Procedure Call) which is the primary inter-process communication "
        "mechanism in NT and is heavily used by both the CSRSS subsystem and anti-cheat components.",
        body_style
    ))
    
    # ════════════════════════════════════════
    # 5. BOOT SEQUENCE
    # ════════════════════════════════════════
    story.append(Paragraph("5. Boot Sequence & Service Group Order", h1_style))
    story.append(Paragraph(
        "The Windows boot process follows a strictly ordered sequence defined by the ServiceGroupOrder registry key. This key "
        "contains a list of 72 driver groups that must be loaded in a specific order. Each driver in the Services key has a "
        "\"Group\" value that places it in one of these groups, and a \"Tag\" value that determines its order within the group. "
        "Understanding this sequence is critical for POLER-OS because the kernel must initialize drivers in the same order to "
        "ensure that dependencies are satisfied. For example, the ACPI driver must load before PCI, which must load before "
        "storage drivers, which must load before the filesystem. Getting this order wrong results in bluescreens or "
        "non-functional hardware. The 93 boot drivers (Start=0) are loaded by the boot loader (winload.exe) before the "
        "kernel even starts, while the 29 system drivers (Start=1) are loaded by IoInitSystem during kernel initialization.",
        body_style
    ))
    
    # Service group order
    story.append(Paragraph("5.1 Service Group Order (First 40 Groups)", h2_style))
    d2 = load_json("deep_analysis_p2.json")
    sgo = d2.get("ServiceGroupOrder", {})
    sgo_list = sgo.get("List", [])
    
    sgo_rows = [[str(i+1), group] for i, group in enumerate(sgo_list[:40])]
    story.append(make_table(["#", "Group Name"], sgo_rows, [40, 420]))
    
    # Boot drivers by group
    story.append(Paragraph("5.2 Boot Drivers by Group", h2_style))
    boot_data = load_json("boot_drivers_detail.json")
    boot_drivers = boot_data.get("boot_drivers", [])
    
    boot_by_group = {}
    for d in boot_drivers:
        grp = d.get("group", "Unknown")
        if grp not in boot_by_group:
            boot_by_group[grp] = []
        boot_by_group[grp].append(d["name"])
    
    bdg_rows = []
    for group in sgo_list:
        if group in boot_by_group:
            drivers = boot_by_group[group]
            bdg_rows.append([group, str(len(drivers)), ", ".join(drivers[:8]) + ("..." if len(drivers) > 8 else "")])
    story.append(make_table(["Group", "Count", "Drivers"], bdg_rows, [130, 40, 290]))
    
    # ════════════════════════════════════════
    # 6. WIN32 SUBSYSTEM
    # ════════════════════════════════════════
    story.append(Paragraph("6. Win32 Subsystem Configuration", h1_style))
    story.append(Paragraph(
        "The Win32 subsystem is the primary user-mode subsystem in Windows NT. Its configuration is stored in the registry "
        "under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems and defines how the Windows subsystem "
        "is initialized. The \"Windows\" value specifies the command line for CSRSS (Client/Server Runtime Subsystem), which "
        "is the first user-mode process created by the kernel. The \"Required\" value lists subsystems that must start "
        "successfully for boot to continue, while \"Optional\" lists subsystems that can fail without preventing boot. "
        "The \"Kmode\" value specifies the kernel-mode portion of the subsystem (win32k.sys), which implements the "
        "window manager and GDI. For POLER-OS, this configuration is essential because it defines the exact process "
        "by which the Win32 environment is brought online, including the server DLLs (basesrv, winsrv, sxssrv) that "
        "CSRSS loads and the shared section parameters that control desktop heap allocation.",
        body_style
    ))
    
    # Subsystem values
    ss_data = d2.get("SessionManager/SubSystems", {})
    ss_rows = []
    for k, v in ss_data.items():
        if not k.startswith("_"):
            vstr = str(v)
            if len(vstr) > 150:
                vstr = vstr[:150] + "..."
            ss_rows.append([k, vstr])
    story.append(make_table(["Value", "Data"], ss_rows, [80, 380]))
    
    # CSRSS command line breakdown
    story.append(Spacer(1, 6))
    story.append(Paragraph("6.1 CSRSS Command Line Breakdown", h2_style))
    csrss_params = [
        ["ObjectDirectory", "\\Windows", "NT object directory for Win32 objects"],
        ["SharedSection", "1024,20480,768", "Desktop heap sizes: shared, interactive, non-interactive (KB)"],
        ["Windows", "On", "Enable windowing subsystem"],
        ["SubSystemType", "Windows", "Subsystem type identifier"],
        ["ServerDll", "basesrv,1", "Base server DLL (console, temp files)"],
        ["ServerDll", "winsrv:UserServerDllInitialization,3", "Window manager server DLL"],
        ["ServerDll", "sxssrv,4", "SxS (side-by-side) server DLL"],
        ["ProfileControl", "Off", "Profiling disabled"],
        ["MaxRequestThreads", "16", "Maximum CSRSS worker threads"],
    ]
    story.append(make_table(["Parameter", "Value", "Description"], csrss_params, [100, 130, 230]))
    
    # ════════════════════════════════════════
    # 7. SESSION MANAGER
    # ════════════════════════════════════════
    story.append(Paragraph("7. Session Manager Configuration", h1_style))
    story.append(Paragraph(
        "The Session Manager (smss.exe) is the first user-mode process created by the NT kernel. It is responsible for "
        "creating the NT object namespace, initializing the KnownDLLs object directory, setting up DOS device mappings, "
        "starting the Win32 subsystem (CSRSS), and creating the initial Windows session. Its configuration in the registry "
        "under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager defines every aspect of the early boot environment. "
        "For POLER-OS, this data is critical because the Session Manager must be one of the first user-mode components "
        "implemented, and it must configure the object namespace and KnownDLLs exactly as Windows does to ensure compatibility "
        "with applications and anti-cheat systems that depend on these namespace conventions.",
        body_style
    ))
    
    # DOS Devices
    story.append(Paragraph("7.1 DOS Device Mappings", h2_style))
    story.append(Paragraph(
        "These mappings define the NT device namespace that Win32 applications see. They are created by the Session Manager "
        "during boot and map DOS-style device names to NT device objects. POLER-OS must create identical symbolic links "
        "in its object manager namespace for Win32 compatibility.",
        body_style
    ))
    dd_data = d2.get("SessionManager/DOS Devices", {})
    dd_rows = [[k, str(v)] for k, v in dd_data.items() if not k.startswith("_")]
    story.append(make_table(["DOS Name", "NT Device Path"], dd_rows, [100, 360]))
    
    # Memory Management
    story.append(Paragraph("7.2 Memory Management Parameters", h2_style))
    mm_data = d2.get("SessionManager/Memory Management", {})
    mm_rows = [[k, str(v)] for k, v in mm_data.items() if not k.startswith("_")]
    story.append(make_table(["Parameter", "Value"], mm_rows, [180, 280]))
    
    # ════════════════════════════════════════
    # 8. CRYPTOGRAPHY
    # ════════════════════════════════════════
    story.append(Paragraph("8. Cryptography Provider Architecture", h1_style))
    story.append(Paragraph(
        "The Windows Cryptography architecture uses Cryptographic Service Providers (CSPs) that implement various "
        "cryptographic algorithms through a plugin system. The registry under HKLM\\SOFTWARE\\Microsoft\\Cryptography "
        "defines the available providers, their types, and the algorithms they support. This is critically important "
        "for POLER-OS because anti-cheat systems use the Windows cryptography APIs to verify game integrity and "
        "authenticate the game client. If the crypto provider architecture is not implemented correctly, anti-cheat "
        "signature verification will fail and the game will be rejected. POLER-OS must implement at minimum the "
        "Microsoft Enhanced RSA and AES Cryptographic Provider and the Microsoft Strong Cryptographic Provider, "
        "along with CNG (Cryptography Next Generation) providers for modern applications.",
        body_style
    ))
    
    # CSP Providers
    story.append(Paragraph("8.1 Cryptographic Service Providers", h2_style))
    prov_data = d2.get("Software/Provider", {})
    prov_sks = prov_data.get("_subkeys", [])
    prov_rows = [[p] for p in prov_sks]
    story.append(make_table(["Provider Name"], prov_rows, [460]))
    
    # Provider Types
    story.append(Paragraph("8.2 Provider Types", h2_style))
    pt_data = d2.get("Software/Provider Types", {})
    pt_sks = pt_data.get("_subkeys", [])
    type_desc = {
        "Type 001": "RSA Full (Signature + Key Exchange)",
        "Type 003": "DSS Signature (DSA)",
        "Type 012": "RSA SChannel (SSL/TLS)",
        "Type 013": "DSS Signature + Diffie-Hellman",
        "Type 018": "Enhanced RSA and AES",
        "Type 024": "CNG (Cryptography Next Generation)"
    }
    pt_rows = [[t, type_desc.get(t, "Unknown")] for t in pt_sks]
    story.append(make_table(["Type", "Description"], pt_rows, [100, 360]))
    
    # ════════════════════════════════════════
    # 9. DEVICE CLASSES
    # ════════════════════════════════════════
    story.append(Paragraph("9. Device Class GUIDs", h1_style))
    story.append(Paragraph(
        "Windows organizes hardware devices into device classes, each identified by a GUID. These class GUIDs are used "
        "throughout the system for driver matching, device installation, and security policy enforcement. The registry "
        "key HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class contains 110 device class entries, each with properties "
        "like the class name, installer DLL, and icon resource. For POLER-OS, these GUIDs must be replicated in the "
        "device enumeration subsystem so that applications and drivers that query device class information receive "
        "the expected data. This is particularly important for anti-cheat systems that check hardware device properties "
        "to detect virtualization or cheating tools.",
        body_style
    ))
    
    dc_data = load_json("device_classes_detail.json")
    dc_rows = []
    for guid, info in sorted(dc_data.items()):
        class_name = info.get("Class", info.get("ClassDesc", "unknown"))
        if isinstance(class_name, str) and len(class_name) > 40:
            class_name = class_name[:40] + "..."
        dc_rows.append([guid, class_name])
    # Show first 30
    story.append(make_table(["GUID", "Class Name"], dc_rows[:30], [280, 180]))
    if len(dc_rows) > 30:
        story.append(Paragraph(f"... and {len(dc_rows) - 30} more device classes", muted_style))
    
    # ════════════════════════════════════════
    # 10. IFEO & ANTI-CHEAT
    # ════════════════════════════════════════
    story.append(Paragraph("10. Image File Execution Options (IFEO)", h1_style))
    story.append(Paragraph(
        "The Image File Execution Options registry key allows the system to intercept and modify process launch behavior. "
        "This is a dual-use mechanism: legitimate debuggers use it to attach to processes, while anti-cheat systems use it "
        "to inject monitoring DLLs into game processes. The key exists at HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options and contains subkeys named after executable files. Each subkey can specify values like "
        "Debugger (redirects process launch to a debugger), MitigationOptions (enables/disables exploit mitigations), and "
        "DisableExceptionChainValidation (modifies exception handling behavior). In the clean Windows 10 installation, we "
        "found 23 IFEO entries, primarily for Internet Explorer and system utilities. Anti-cheat systems like EasyAntiCheat "
        "and BattlEye add their own IFEO entries at install time. POLER-OS must implement IFEO support to allow anti-cheat "
        "DLLs to inject into game processes, as this is one of the primary methods they use for monitoring.",
        body_style
    ))
    
    ifeo_data = load_json("ifeo_detail.json")
    ifeo_rows = []
    for exe, opts in ifeo_data.items():
        opt_str = ", ".join(f"{k}={v}" for k, v in opts.items())
        if len(opt_str) > 100:
            opt_str = opt_str[:100] + "..."
        ifeo_rows.append([exe, opt_str])
    story.append(make_table(["Executable", "Options"], ifeo_rows, [150, 310]))
    
    # ════════════════════════════════════════
    # 11. FILE SYSTEM
    # ════════════════════════════════════════
    story.append(Paragraph("11. File System Parameters", h1_style))
    story.append(Paragraph(
        "The file system configuration in HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem defines how NTFS and ReFS "
        "behave at the kernel level. These parameters control features like 8.3 name generation, last access time updates, "
        "encryption, compression, and symlink evaluation. For POLER-OS, these parameters directly inform the POLER-FS "
        "implementation. The most significant finding is that NtfsDisableLastAccessUpdate is set to 1 by default, meaning "
        "NTFS no longer updates the last access timestamp on reads, which is a significant performance optimization that "
        "POLER-FS should replicate. Additionally, NtfsDisable8dot3NameCreation is set to 2 (volume-dependent), meaning "
        "short name generation is optional and should be disabled on the system volume for performance. Symlink evaluation "
        "settings show that local-to-local and local-to-remote symlinks are enabled by default, while remote-to-local and "
        "remote-to-remote are disabled for security.",
        body_style
    ))
    
    fs_data = d2.get("Control/FileSystem", {})
    fs_rows = [[k, str(v)] for k, v in fs_data.items() if not k.startswith("_")]
    story.append(make_table(["Parameter", "Value"], fs_rows, [220, 240]))
    
    # ════════════════════════════════════════
    # 12. LSA & SECURITY
    # ════════════════════════════════════════
    story.append(Paragraph("12. Local Security Authority (LSA)", h1_style))
    story.append(Paragraph(
        "The LSA configuration defines authentication packages, notification packages, and security packages. The "
        "authentication package msv1_0 handles NTLM authentication, while the notification package scecli handles "
        "security policy updates. The Security Packages list defines which SSP (Security Support Provider) DLLs are "
        "loaded into the LSA process. In the clean install, this is empty (populated at runtime with kerberos, "
        "msv1_0, schannel, wdigest, tspkg, pku2u, and cloudAP). For POLER-OS, the LSA architecture must be "
        "implemented because anti-cheat systems use the LSA authentication APIs to verify the integrity of the "
        "logon session and detect token manipulation. The NoLmHash=1 setting indicates that LM hash storage is "
        "disabled, which is the modern security default that POLER-OS should follow. The LimitBlankPasswordUse=1 "
        "setting prevents remote authentication with blank passwords, another security default to replicate.",
        body_style
    ))
    
    lsa_data = d2.get("Control/Lsa", {})
    lsa_rows = [[k, str(v)] for k, v in lsa_data.items() if not k.startswith("_")]
    story.append(make_table(["Parameter", "Value"], lsa_rows, [200, 260]))
    
    # ════════════════════════════════════════
    # 13. NT VERSION
    # ════════════════════════════════════════
    story.append(Paragraph("13. Windows NT Version Information", h1_style))
    story.append(Paragraph(
        "The Windows NT CurrentVersion key contains the operating system version information that applications query "
        "to determine compatibility. The CurrentVersion value is 6.3 (the internal NT version for Windows 10), while "
        "the CurrentBuild is 19045 (the public build number). The BuildLab value (19041.vb_release.191206-1406) "
        "identifies the exact build configuration. The UBR (Update Build Revision) value of 2965 identifies the "
        "specific cumulative update level. For POLER-OS, these values must be spoofed correctly because applications "
        "and anti-cheat systems check the OS version to determine feature availability and compatibility. Reporting "
        "an incorrect version can cause applications to refuse to run or to use incompatible code paths.",
        body_style
    ))
    
    ntcv = load_json("nt_currentversion_detail.json")
    ntcv_rows = []
    important_keys = ["CurrentVersion", "CurrentBuild", "CurrentBuildNumber", "BuildLab", "BuildLabEx",
                      "CurrentType", "InstallationType", "EditionID", "ProductName", "UBR",
                      "PathName", "SystemRoot", "DigitalProductId"]
    for k in important_keys:
        if k in ntcv:
            v = str(ntcv[k])
            if len(v) > 80:
                v = v[:80] + "..."
            ntcv_rows.append([k, v])
    story.append(make_table(["Key", "Value"], ntcv_rows, [150, 310]))
    
    # ════════════════════════════════════════
    # 14. IMPLEMENTATION PRIORITY
    # ════════════════════════════════════════
    story.append(Paragraph("14. POLER-OS Implementation Priority", h1_style))
    story.append(Paragraph(
        "Based on the registry analysis, the following implementation priority is recommended for the POLER-OS NT API "
        "compatibility layer. The priorities are ordered by the impact on Win32 application compatibility and anti-cheat "
        "support. Each phase builds on the previous one, and skipping phases will result in applications failing to load "
        "or crashing at runtime.",
        body_style
    ))
    
    priority_rows = [
        ["P0", "Object Manager", "Namespace, symlinks, DOS devices, KnownDLLs directory", "All apps depend on object namespace"],
        ["P0", "Process/Thread", "NtCreateProcess, NtCreateThreadEx, NtTerminateProcess", "No app can run without this"],
        ["P0", "Memory Manager", "NtAllocateVirtualMemory, NtProtectVirtualMemory, sections", "Fundamental for all code execution"],
        ["P0", "File System", "NtCreateFile, NtReadFile, NtWriteFile, POLER-FS integration", "No I/O without this"],
        ["P1", "API Set Layer", "api-ms-win-* DLL redirection, apisetchema.dll parser", "Modern apps won't load without it"],
        ["P1", "Registry", "NtCreateKey, NtSetValueKey, NtQueryValueKey, hive format", "All configuration depends on registry"],
        ["P1", "Synchronization", "NtCreateEvent, NtCreateMutant, NtWaitForSingleObject", "Multi-threading impossible without it"],
        ["P1", "KnownDLLs", "Force-load 29 system DLLs from System32 only", "Security requirement for anti-cheat"],
        ["P2", "IPC/ALPC", "NtCreatePort, NtConnectPort, NtRequestWaitReplyPort", "Required for CSRSS and service communication"],
        ["P2", "Security/Token", "NtOpenProcessToken, NtAccessCheck, LSA integration", "Anti-cheat authentication depends on this"],
        ["P2", "Win32k", "win32k.sys kernel-mode GDI/Window manager", "Required for any GUI application"],
        ["P2", "CSP/CNG", "Crypto providers, bcrypt, ncrypt", "Anti-cheat signature verification"],
        ["P3", "IFEO", "Process interception, MitigationOptions", "Anti-cheat DLL injection mechanism"],
        ["P3", "WMI", "WMI provider hosting, ETW tracing", "Anti-cheat monitoring infrastructure"],
        ["P3", "Device Classes", "GUID enumeration, device installation", "Hardware detection and anti-cheat checks"],
    ]
    story.append(make_table(["Priority", "Subsystem", "Key Functions", "Rationale"], priority_rows, [40, 90, 190, 140]))
    
    # ════════════════════════════════════════
    # 15. WINLOGON
    # ════════════════════════════════════════
    story.append(Paragraph("15. Winlogon Configuration", h1_style))
    story.append(Paragraph(
        "Winlogon is responsible for interactive logon, shell startup, and screen saver security. Its configuration "
        "defines the shell (explorer.exe), user initialization (userinit.exe), and various security policies. For POLER-OS, "
        "the Winlogon configuration is important because it defines the user-mode entry point after kernel initialization. "
        "The Shell value specifies the application that Winlogon starts after authentication - by default this is explorer.exe, "
        "but POLER-OS could replace this with its own shell. The Userinit value specifies the program that initializes the "
        "user environment before the shell starts. The AutoRestartShell=1 setting means that if the shell crashes, Winlogon "
        "will automatically restart it, which is important for system stability.",
        body_style
    ))
    
    wl_data = d2.get("Software/Winlogon", {})
    wl_rows = [[k, str(v)] for k, v in wl_data.items() if not k.startswith("_")][:15]
    story.append(make_table(["Parameter", "Value"], wl_rows, [160, 300]))
    
    # ════════════════════════════════════════
    # BUILD PDF
    # ════════════════════════════════════════
    doc.build(story)
    print(f"PDF generated: {output_path}")
    return output_path


if __name__ == "__main__":
    path = build_report()
