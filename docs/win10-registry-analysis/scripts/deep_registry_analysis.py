#!/usr/bin/env python3
"""
Deep Windows 10 Registry Analysis for POLER-OS
Parses raw hive files to extract data that reg export misses,
especially ApiSetMap (binary), KnownDLLs dependencies, and service structures.
"""

import os
import sys
import json
import struct
from collections import defaultdict

# Try python-registry first
try:
    from Registry import Registry
    HAS_PYREG = True
except ImportError:
    HAS_PYREG = False
    print("WARNING: python-registry not available, some analysis will be limited")

# Try regipy
try:
    from regipy.registry import RegistryHive
    from regipy.exceptions import RegistryKeyNotFoundException
    HAS_REGIPY = True
except ImportError:
    HAS_REGIPY = False
    print("WARNING: regipy not available")

# Try dissect
try:
    from dissect.regf import RegistryHive as DissectHive
    HAS_DISSECT = True
except ImportError:
    HAS_DISSECT = False
    print("WARNING: dissect not available")

HIVE_DIR = "/home/z/my-project/registry-analysis/extracted/RegistryHives"
OUTPUT_DIR = "/home/z/my-project/registry-analysis/results"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def safe_name(name):
    """Clean up registry key/value names for JSON output"""
    if isinstance(name, bytes):
        try:
            return name.decode('utf-16-le').rstrip('\x00')
        except:
            return name.hex()
    return str(name)


def parse_known_dlls():
    """Extract KnownDLLs with full details including path and type"""
    print("\n" + "="*60)
    print("ANALYZING: KnownDLLs")
    print("="*60)
    
    results = {}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            # Navigate to ControlSet001\Control\Session Manager\KnownDLLs
            key = reg.open("ControlSet001\\Control\\Session Manager\\KnownDLLs")
            
            for val in key.values():
                name = val.name()
                value = val.value()
                vtype = val.value_type()
                results[name] = {
                    "value": safe_name(value) if isinstance(value, bytes) else str(value),
                    "type": str(vtype)
                }
            
            print(f"  Found {len(results)} KnownDLLs entries")
            
            # Also get KnownDlls32 if it exists
            try:
                key32 = reg.open("ControlSet001\\Control\\Session Manager\\KnownDlls32")
                results_32 = {}
                for val in key32.values():
                    name = val.name()
                    value = val.value()
                    results_32[name] = {
                        "value": safe_name(value) if isinstance(value, bytes) else str(value),
                    }
                results["_KnownDlls32"] = results_32
                print(f"  Found {len(results_32)} KnownDlls32 entries")
            except:
                print("  KnownDlls32 not found (expected)")
                
        except Exception as e:
            print(f"  Error: {e}")
    
    # Save
    with open(os.path.join(OUTPUT_DIR, "knowndlls_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    return results


def parse_apiset_map():
    """
    CRITICAL: ApiSetMap is stored as binary data in the registry.
    The .reg export is empty because the data is in a special binary format.
    We need to parse the ApiSetMap structure manually.
    """
    print("\n" + "="*60)
    print("ANALYZING: ApiSetMap (BINARY PARSING)")
    print("="*60)
    
    results = {
        "api_sets": {},
        "notes": "ApiSetMap maps api-ms-win-* DLL names to real implementation DLLs"
    }
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            key = reg.open("ControlSet001\\Control\\ApiSetMap")
            
            print(f"  ApiSetMap key has {len(key.subkeys())} subkeys")
            
            for subkey in key.subkeys():
                api_name = subkey.name()
                entries = {}
                
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    vtype = val.value_type()
                    
                    # The value might be a string or binary
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            vvalue = vvalue.hex()
                    else:
                        vvalue = str(vvalue)
                    
                    entries[vname] = vvalue
                
                results["api_sets"][api_name] = entries
            
            print(f"  Parsed {len(results['api_sets'])} API Set mappings")
            
            # Show some examples
            for i, (name, vals) in enumerate(results["api_sets"].items()):
                if i < 5:
                    print(f"    {name} -> {vals}")
            
        except Exception as e:
            print(f"  Error parsing ApiSetMap: {e}")
            import traceback
            traceback.print_exc()
    
    # Also try to read the raw binary value if it exists
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            key = reg.open("ControlSet001\\Control\\ApiSetMap")
            
            for val in key.values():
                if val.name() == "ApiSetMap" or val.name() == "":
                    raw = val.raw_value()
                    if raw:
                        print(f"  Found raw ApiSetMap binary data: {len(raw)} bytes")
                        results["raw_data_size"] = len(raw)
                        results["raw_data_hex"] = raw[:200].hex()
        except Exception as e:
            print(f"  No raw ApiSetMap data: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "apisetmap_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    return results


def parse_services():
    """Deep analysis of NT services and drivers"""
    print("\n" + "="*60)
    print("ANALYZING: Services & Drivers")
    print("="*60)
    
    results = {
        "by_type": defaultdict(list),
        "by_start_type": defaultdict(list),
        "by_group": defaultdict(list),
        "with_dependencies": {},
        "boot_drivers": [],
        "filesystem_drivers": [],
        "total_count": 0
    }
    
    # Start type mapping
    START_TYPES = {
        0: "BOOT (loaded by boot loader)",
        1: "SYSTEM (loaded by IoInitSystem)",
        2: "AUTOMATIC (loaded by Service Control Manager)",
        3: "MANUAL (loaded on demand)",
        4: "DISABLED"
    }
    
    # Service type mapping
    SERVICE_TYPES = {
        1: "KERNEL_DRIVER",
        2: "FILE_SYSTEM_DRIVER",
        16: "OWN_PROCESS",
        32: "SHARE_PROCESS",
        256: "INTERACTIVE_PROCESS"
    }
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            key = reg.open("ControlSet001\\Services")
            
            for subkey in key.subkeys():
                name = subkey.name()
                results["total_count"] += 1
                
                # Extract key values
                svc_info = {"name": name}
                
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            if len(vvalue) <= 8:
                                vvalue = int.from_bytes(vvalue, 'little')
                            else:
                                vvalue = f"[binary:{len(vvalue)}bytes]"
                    
                    svc_info[vname] = vvalue
                
                # Categorize
                start = svc_info.get("Start", -1)
                if isinstance(start, int):
                    results["by_start_type"][START_TYPES.get(start, f"UNKNOWN({start})")].append(name)
                    if start == 0:
                        results["boot_drivers"].append(name)
                
                svc_type = svc_info.get("Type", -1)
                if isinstance(svc_type, int):
                    type_name = SERVICE_TYPES.get(svc_type, f"UNKNOWN({svc_type})")
                    results["by_type"][type_name].append(name)
                    if svc_type == 2:
                        results["filesystem_drivers"].append(name)
                
                group = svc_info.get("Group", "")
                if group:
                    results["by_group"][group].append(name)
                
                # Dependencies
                deps = svc_info.get("DependOnGroup", "") or svc_info.get("DependOnService", "")
                if deps:
                    results["with_dependencies"][name] = deps
            
            print(f"  Total services/drivers: {results['total_count']}")
            print(f"  Boot drivers: {len(results['boot_drivers'])}")
            print(f"  Filesystem drivers: {len(results['filesystem_drivers'])}")
            print(f"  Kernel drivers: {len(results['by_type'].get('KERNEL_DRIVER', []))}")
            print(f"  By start type:")
            for stype, svcs in results["by_start_type"].items():
                print(f"    {stype}: {len(svcs)}")
            
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
    
    with open(os.path.join(OUTPUT_DIR, "services_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_nt_currentversion():
    """Deep analysis of Windows NT CurrentVersion"""
    print("\n" + "="*60)
    print("ANALYZING: Windows NT CurrentVersion")
    print("="*60)
    
    results = {}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SOFTWARE.hiv"))
            key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
            
            for val in key.values():
                name = val.name()
                value = val.value()
                
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-16-le').rstrip('\x00')
                    except:
                        if len(value) <= 8:
                            value = int.from_bytes(value, 'little')
                        else:
                            value = f"[binary:{len(value)}bytes]"
                
                results[name] = str(value) if not isinstance(value, str) else value
            
            # Key subkeys
            subkey_names = [sk.name() for sk in key.subkeys()]
            results["_subkeys"] = subkey_names
            
            # Important specific values
            important = [
                "CurrentVersion", "CurrentBuild", "CurrentBuildNumber",
                "BuildLab", "BuildLabEx", "CurrentType",
                "InstallationType", "EditionID", "ProductName",
                "SubVersionNumber", "UBR", "DigitalProductId",
                "PathName", "SystemRoot"
            ]
            
            print("  Key values:")
            for k in important:
                if k in results:
                    v = results[k]
                    if len(str(v)) > 100:
                        v = str(v)[:100] + "..."
                    print(f"    {k} = {v}")
            
            print(f"  Subkeys ({len(subkey_names)}): {subkey_names[:20]}...")
            
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
    
    with open(os.path.join(OUTPUT_DIR, "nt_currentversion_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_cryptography():
    """Deep analysis of Cryptography providers"""
    print("\n" + "="*60)
    print("ANALYZING: Cryptography")
    print("="*60)
    
    results = {}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SOFTWARE.hiv"))
            key = reg.open("Microsoft\\Cryptography")
            
            for val in key.values():
                name = val.name()
                value = val.value()
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-16-le').rstrip('\x00')
                    except:
                        value = f"[binary:{len(value)}bytes]"
                results[name] = str(value)
            
            # Subkeys
            for subkey in key.subkeys():
                sk_name = subkey.name()
                sk_data = {}
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            vvalue = f"[binary:{len(vvalue)}bytes]"
                    sk_data[vname] = str(vvalue)
                results[sk_name] = sk_data
            
            # Also parse Providers
            try:
                providers_key = reg.open("Microsoft\\Cryptography\\Providers")
                for subkey in providers_key.subkeys():
                    cat_name = subkey.name()
                    results[f"Providers/{cat_name}"] = [sk.name() for sk in subkey.subkeys()]
            except:
                pass
            
            # Defaults
            try:
                defaults_key = reg.open("Microsoft\\Cryptography\\Defaults")
                for subkey in defaults_key.subkeys():
                    cat_name = subkey.name()
                    providers = {}
                    for prov in subkey.subkeys():
                        prov_data = {}
                        for val in prov.values():
                            vname = val.name()
                            vvalue = val.value()
                            if isinstance(vvalue, bytes):
                                try:
                                    vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                                except:
                                    vvalue = f"[binary:{len(vvalue)}bytes]"
                            prov_data[vname] = str(vvalue)
                        providers[prov.name()] = prov_data
                    results[f"Defaults/{cat_name}"] = providers
            except Exception as e:
                print(f"  Defaults error: {e}")
            
            print(f"  Top-level keys: {list(results.keys())[:20]}")
            
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
    
    with open(os.path.join(OUTPUT_DIR, "cryptography_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_sxs():
    """Analyze Side-by-Side assembly information"""
    print("\n" + "="*60)
    print("ANALYZING: SideBySide (WinSxS)")
    print("="*60)
    
    results = {"components": [], "policies": [], "assemblies": []}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SOFTWARE.hiv"))
            
            # WinSxS manifests and assemblies
            try:
                sxs_key = reg.open("Microsoft\\Windows\\CurrentVersion\\SideBySide")
                
                for val in sxs_key.values():
                    name = val.name()
                    value = val.value()
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-16-le').rstrip('\x00')
                        except:
                            value = f"[binary:{len(value)}bytes]"
                    results[f"root_{name}"] = str(value)
                
                # Parse Installers subkey
                for subkey in sxs_key.subkeys():
                    sk_name = subkey.name()
                    if sk_name in ("Installers", "AssemblyStorageRoots", "Winners"):
                        count = len(list(subkey.subkeys()))
                        results[f"{sk_name}_count"] = count
                        # Sample some
                        samples = [sk.name() for sk in list(subkey.subkeys())[:10]]
                        results[f"{sk_name}_samples"] = samples
                
            except Exception as e:
                print(f"  SideBySide error: {e}")
            
            # COMPONENTS hive has more SxS data
            try:
                comp_reg = Registry.Registry(os.path.join(HIVE_DIR, "COMPONENTS.hiv"))
                root = comp_reg.open(".")
                for subkey in root.subkeys():
                    results["components_root_subkeys"] = results.get("components_root_subkeys", [])
                    results["components_root_subkeys"].append(subkey.name())
                
                # Parse ComponentBasedServicing
                try:
                    cbs = comp_reg.open("ComponentBasedServicing")
                    for subkey in cbs.subkeys():
                        sk_name = subkey.name()
                        cnt = len(list(subkey.subkeys()))
                        results[f"CBS/{sk_name}"] = cnt
                except:
                    pass
                    
                # Parse Packages
                try:
                    packages = comp_reg.open("ComponentBasedServicing\\Packages")
                    pkg_list = []
                    for i, subkey in enumerate(packages.subkeys()):
                        if i < 50:  # Sample first 50
                            pkg_info = {"name": subkey.name()}
                            for val in subkey.values():
                                if val.name() in ("CurrentState", "InstallClient", "InstallName", "InstallLocation"):
                                    v = val.value()
                                    if isinstance(v, int):
                                        pkg_info[val.name()] = v
                                    elif isinstance(v, bytes):
                                        try:
                                            pkg_info[val.name()] = v.decode('utf-16-le').rstrip('\x00')
                                        except:
                                            pkg_info[val.name()] = f"[binary:{len(v)}bytes]"
                                    else:
                                        pkg_info[val.name()] = str(v)
                            pkg_list.append(pkg_info)
                    results["packages_sample"] = pkg_list
                    results["packages_total"] = len(list(packages.subkeys()))
                except Exception as e:
                    print(f"  Packages error: {e}")
                    
            except Exception as e:
                print(f"  COMPONENTS hive error: {e}")
            
            print(f"  SxS root values: {len([k for k in results if k.startswith('root_')])}")
            print(f"  CBS packages total: {results.get('packages_total', 'N/A')}")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "sxs_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_ifeo():
    """Analyze Image File Execution Options - critical for anti-cheat"""
    print("\n" + "="*60)
    print("ANALYZING: Image File Execution Options (IFEO)")
    print("="*60)
    
    results = {}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SOFTWARE.hiv"))
            key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
            
            for subkey in key.subkeys():
                exe_name = subkey.name()
                opts = {}
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            vvalue = f"[binary:{len(vvalue)}bytes]"
                    opts[vname] = str(vvalue)
                results[exe_name] = opts
            
            print(f"  IFEO entries: {len(results)}")
            for name, opts in list(results.items())[:10]:
                print(f"    {name}: {opts}")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "ifeo_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_ntdll_exports():
    """Classify ntdll exports into NtXxx, ZwXxx, RtlXxx categories"""
    print("\n" + "="*60)
    print("ANALYZING: ntdll.dll exports")
    print("="*60)
    
    results = {
        "nt_functions": [],      # NtXxx - system calls
        "zw_functions": [],      # ZwXxx - kernel-mode system calls
        "rtl_functions": [],     # RtlXxx - runtime library
        "other_functions": [],   # Everything else
        "summary": {}
    }
    
    ntdll_file = "/home/z/my-project/registry-analysis/extracted/RegistryExport/ntdll_exports.txt"
    
    if os.path.exists(ntdll_file):
        with open(ntdll_file, "r") as f:
            for line in f:
                line = line.strip()
                # Look for function names in the dumpbin-style output
                # Format is typically: ordinal hint RVA name
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[-1]
                    if name.startswith("Nt") and not name.startswith("Ntdll"):
                        results["nt_functions"].append(name)
                    elif name.startswith("Zw"):
                        results["zw_functions"].append(name)
                    elif name.startswith("Rtl"):
                        results["rtl_functions"].append(name)
                    elif name.startswith(("Etwp", "Pss", "Tpp", "Wer", "Alpc", "Dbg")):
                        results["other_functions"].append(name)
        
        results["summary"] = {
            "total_nt": len(results["nt_functions"]),
            "total_zw": len(results["zw_functions"]),
            "total_rtl": len(results["rtl_functions"]),
            "total_other": len(results["other_functions"]),
            "nt_zw_pairs": len(set(f.replace("Nt", "Zw", 1) for f in results["nt_functions"]) & set(results["zw_functions"]))
        }
        
        print(f"  NtXxx functions: {len(results['nt_functions'])}")
        print(f"  ZwXxx functions: {len(results['zw_functions'])}")
        print(f"  RtlXxx functions: {len(results['rtl_functions'])}")
        print(f"  Other functions: {len(results['other_functions'])}")
        print(f"  Nt/Zw pairs: {results['summary']['nt_zw_pairs']}")
    
    with open(os.path.join(OUTPUT_DIR, "ntdll_analysis.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    return results


def parse_device_classes():
    """Analyze device class GUIDs"""
    print("\n" + "="*60)
    print("ANALYZING: Device Classes")
    print("="*60)
    
    results = {}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            key = reg.open("ControlSet001\\Control\\Class")
            
            for subkey in key.subkeys():
                guid = subkey.name()
                info = {"subkeys": [sk.name() for sk in list(subkey.subkeys())[:5]]}
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            vvalue = f"[binary:{len(vvalue)}bytes]"
                    info[vname] = str(vvalue)
                results[guid] = info
            
            print(f"  Device classes: {len(results)}")
            for guid, info in list(results.items())[:5]:
                class_name = info.get("Class", info.get("ClassDesc", "unknown"))
                print(f"    {guid}: {class_name}")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "device_classes_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_session_manager():
    """Extract Session Manager details - critical for OS boot"""
    print("\n" + "="*60)
    print("ANALYZING: Session Manager")
    print("="*60)
    
    results = {}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            key = reg.open("ControlSet001\\Control\\Session Manager")
            
            for val in key.values():
                name = val.name()
                value = val.value()
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-16-le').rstrip('\x00')
                    except:
                        if len(value) <= 8:
                            value = int.from_bytes(value, 'little')
                        else:
                            value = f"[binary:{len(value)}bytes]"
                results[name] = str(value) if not isinstance(value, int) else value
            
            # Subkeys
            for subkey in key.subkeys():
                sk_name = subkey.name()
                sk_data = {}
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            vvalue = f"[binary:{len(vvalue)}bytes]"
                    sk_data[vname] = str(vvalue)
                results[f"_{sk_name}"] = sk_data
            
            print(f"  Values: {[k for k in results if not k.startswith('_')]}")
            print(f"  Subkeys: {[k for k in results if k.startswith('_')]}")
            
            # Key values for POLER-OS
            critical_keys = [
                "BootExecute", "CriticalSectionTimeout", "GlobalFlag",
                "HeapDeCommitFreeBlockThreshold", "HeapDeCommitTotalFreeThreshold",
                "HeapSegmentCommit", "HeapSegmentReserve", "ObjectDirectories",
                "ResourceTimeoutCount", "RegisteredProcessors"
            ]
            print("  Critical values:")
            for ck in critical_keys:
                if ck in results:
                    print(f"    {ck} = {results[ck]}")
            
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
    
    with open(os.path.join(OUTPUT_DIR, "session_manager_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_wmi():
    """Analyze WMI providers - anti-cheat uses these for monitoring"""
    print("\n" + "="*60)
    print("ANALYZING: WMI Providers")
    print("="*60)
    
    results = {"providers": []}
    
    if HAS_PYREG:
        try:
            reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
            key = reg.open("ControlSet001\\Control\\WMI")
            
            for subkey in key.subkeys():
                sk_name = subkey.name()
                info = {"name": sk_name}
                
                for val in subkey.values():
                    vname = val.name()
                    vvalue = val.value()
                    if isinstance(vvalue, bytes):
                        try:
                            vvalue = vvalue.decode('utf-16-le').rstrip('\x00')
                        except:
                            vvalue = f"[binary:{len(vvalue)}bytes]"
                    info[vname] = str(vvalue)
                
                # Count deeper subkeys
                sub_count = len(list(subkey.subkeys()))
                info["subkey_count"] = sub_count
                
                results["providers"].append(info)
            
            print(f"  WMI entries: {len(results['providers'])}")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "wmi_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_apiset_dlls():
    """Analyze the API Set DLL list"""
    print("\n" + "="*60)
    print("ANALYZING: API Set DLLs")
    print("="*60)
    
    results = {
        "api_ms_win": [],
        "ext_ms_win": [],
        "by_category": defaultdict(list)
    }
    
    apiset_file = "/home/z/my-project/registry-analysis/extracted/RegistryExport/apiset_dlls.txt"
    
    if os.path.exists(apiset_file):
        with open(apiset_file, "r") as f:
            for line in f:
                dll = line.strip()
                if not dll:
                    continue
                if dll.startswith("api-ms-win-"):
                    results["api_ms_win"].append(dll)
                    # Extract category (e.g., api-ms-win-core-...)
                    parts = dll.split("-")
                    if len(parts) >= 4:
                        cat = "-".join(parts[:4])  # e.g., api-ms-win-core
                        results["by_category"][cat].append(dll)
                elif dll.startswith("ext-ms-win-"):
                    results["ext_ms_win"].append(dll)
    
    results["summary"] = {
        "total_api_ms_win": len(results["api_ms_win"]),
        "total_ext_ms_win": len(results["ext_ms_win"]),
        "categories": {cat: len(dlls) for cat, dlls in sorted(results["by_category"].items(), key=lambda x: -len(x[1]))[:20]}
    }
    
    print(f"  api-ms-win-* DLLs: {len(results['api_ms_win'])}")
    print(f"  ext-ms-win-* DLLs: {len(results['ext_ms_win'])}")
    print(f"  Top categories:")
    for cat, dlls in sorted(results["by_category"].items(), key=lambda x: -len(x[1]))[:10]:
        print(f"    {cat}: {len(dlls)}")
    
    with open(os.path.join(OUTPUT_DIR, "apiset_dlls_analysis.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_system32_dlls():
    """Analyze System32 DLL list"""
    print("\n" + "="*60)
    print("ANALYZING: System32 DLLs")
    print("="*60)
    
    results = {
        "total": 0,
        "by_prefix": defaultdict(int),
        "key_dlls": {}
    }
    
    dll_file = "/home/z/my-project/registry-analysis/extracted/RegistryExport/system32_dlls.txt"
    
    if os.path.exists(dll_file):
        with open(dll_file, "r") as f:
            for line in f:
                dll = line.strip().lower()
                if not dll:
                    continue
                results["total"] += 1
                
                # Categorize by prefix
                prefix = dll.split("_")[0].split("-")[0][:6]
                results["by_prefix"][prefix] += 1
                
                # Flag key DLLs for POLER-OS
                key_dlls = [
                    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
                    "user32.dll", "gdi32.dll", "advapi32.dll",
                    "ws2_32.dll", "crypt32.dll", "bcrypt.dll",
                    "bcryptprimitives.dll", "ncrypt.dll",
                    "msvcrt.dll", "ucrtbase.dll",
                    "ole32.dll", "combase.dll", "shell32.dll",
                    "shlwapi.dll", "version.dll", "wintrust.dll",
                    "api-ms-win-core-synch-l1-2-0.dll",
                    "apisetschema.dll", "wow64.dll", "wow64win.dll",
                    "wow64cpu.dll", "ntmarta.dll"
                ]
                if dll in key_dlls:
                    results["key_dlls"][dll] = True
    
    print(f"  Total DLLs: {results['total']}")
    print(f"  Key DLLs found: {len(results['key_dlls'])}")
    
    with open(os.path.join(OUTPUT_DIR, "system32_dlls_analysis.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def generate_summary(all_results):
    """Generate a POLER-OS focused summary"""
    print("\n" + "="*60)
    print("GENERATING: POLER-OS Registry Analysis Summary")
    print("="*60)
    
    summary = {
        "metadata": {
            "source": "Windows 10 22H2 English x64",
            "hive_files_analyzed": ["SYSTEM", "SOFTWARE", "COMPONENTS"],
            "analysis_date": "2026-07-18"
        },
        "for_poler_os": {
            "api_set_mapping": {
                "total_api_sets": len(all_results.get("apisetmap", {}).get("api_sets", {})),
                "total_api_ms_win_dlls": all_results.get("apiset_dlls", {}).get("summary", {}).get("total_api_ms_win", 0),
                "total_ext_ms_win_dlls": all_results.get("apiset_dlls", {}).get("summary", {}).get("total_ext_ms_win", 0),
                "top_categories": all_results.get("apiset_dlls", {}).get("summary", {}).get("categories", {}),
                "implementation_note": "ApiSetMap maps virtual api-ms-win-* DLL names to real implementation DLLs. POLER-OS must implement this mapping layer for Win32 compatibility."
            },
            "known_dlls": {
                "count": len([k for k in all_results.get("knowndlls", {}) if not k.startswith("_")]),
                "implementation_note": "These DLLs are force-loaded from System32. POLER-OS must maintain this list to prevent DLL injection attacks."
            },
            "boot_drivers": {
                "count": len(all_results.get("services", {}).get("boot_drivers", [])),
                "implementation_note": "These drivers load at boot time. POLER-OS needs equivalent kernel modules for hardware init."
            },
            "filesystem_drivers": {
                "count": len(all_results.get("services", {}).get("filesystem_drivers", [])),
                "list": all_results.get("services", {}).get("filesystem_drivers", [])
            },
            "ntdll": all_results.get("ntdll", {}).get("summary", {}),
            "cryptography": {
                "note": "CSP providers and algorithms used by Windows. POLER-OS crypto subsystem must be compatible."
            },
            "session_manager": {
                "critical_keys": ["BootExecute", "GlobalFlag", "ObjectDirectories"],
                "implementation_note": "Session Manager is the first user-mode process. POLER-OS needs equivalent for subsystem initialization."
            }
        }
    }
    
    with open(os.path.join(OUTPUT_DIR, "poleros_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
    
    print("  Summary saved to poleros_summary.json")
    return summary


def main():
    print("="*60)
    print("POLER-OS: Deep Windows 10 Registry Analysis")
    print("Source: Windows 10 22H2 English x64")
    print("="*60)
    
    all_results = {}
    
    # Parse each critical section
    all_results["knowndlls"] = parse_known_dlls()
    all_results["apisetmap"] = parse_apiset_map()
    all_results["services"] = parse_services()
    all_results["nt_currentversion"] = parse_nt_currentversion()
    all_results["cryptography"] = parse_cryptography()
    all_results["sxs"] = parse_sxs()
    all_results["ifeo"] = parse_ifeo()
    all_results["ntdll"] = parse_ntdll_exports()
    all_results["device_classes"] = parse_device_classes()
    all_results["session_manager"] = parse_session_manager()
    all_results["wmi"] = parse_wmi()
    all_results["apiset_dlls"] = parse_apiset_dlls()
    all_results["system32_dlls"] = parse_system32_dlls()
    
    # Generate summary
    summary = generate_summary(all_results)
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print(f"Results saved to: {OUTPUT_DIR}")
    print("="*60)


if __name__ == "__main__":
    main()
