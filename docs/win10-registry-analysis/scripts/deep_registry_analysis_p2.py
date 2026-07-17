#!/usr/bin/env python3
"""
Deep Registry Analysis Part 2: Session Manager internals, SubSystems,
Memory Management, ApiSetSchema, and boot-time configuration.
"""

import os
import sys
import json
import struct
from collections import defaultdict

from Registry import Registry

HIVE_DIR = "/home/z/my-project/registry-analysis/extracted/RegistryHives"
OUTPUT_DIR = "/home/z/my-project/registry-analysis/results"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def safe_value(vvalue):
    """Convert registry value to safe JSON-compatible format"""
    if isinstance(vvalue, bytes):
        try:
            return vvalue.decode('utf-16-le').rstrip('\x00')
        except:
            if len(vvalue) <= 8:
                return int.from_bytes(vvalue, 'little')
            return f"[binary:{len(vvalue)}bytes]"
    elif isinstance(vvalue, int):
        return vvalue
    elif isinstance(vvalue, list):
        return [safe_value(v) for v in vvalue]
    return str(vvalue)


def parse_subkey_recursive(reg, path, max_depth=3, current_depth=0):
    """Recursively parse a registry key and all its subkeys"""
    try:
        key = reg.open(path)
    except:
        return None
    
    result = {"_values": {}, "_subkeys": {}}
    
    for val in key.values():
        result["_values"][val.name()] = safe_value(val.value())
    
    if current_depth < max_depth:
        for subkey in key.subkeys():
            sk_name = subkey.name()
            sk_path = f"{path}\\{sk_name}"
            result["_subkeys"][sk_name] = parse_subkey_recursive(reg, sk_path, max_depth, current_depth + 1)
    else:
        result["_subkeys"] = [sk.name() for sk in key.subkeys()]
    
    return result


def parse_session_manager_deep():
    """Deep dive into all Session Manager subkeys"""
    print("\n" + "="*60)
    print("DEEP DIVE: Session Manager SubSystems & Memory Management")
    print("="*60)
    
    results = {}
    reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
    
    sm_paths = [
        "ControlSet001\\Control\\Session Manager\\SubSystems",
        "ControlSet001\\Control\\Session Manager\\Memory Management",
        "ControlSet001\\Control\\Session Manager\\Executive",
        "ControlSet001\\Control\\Session Manager\\DOS Devices",
        "ControlSet001\\Control\\Session Manager\\Environment",
        "ControlSet001\\Control\\Session Manager\\I/O System",
        "ControlSet001\\Control\\Session Manager\\kernel",
        "ControlSet001\\Control\\Session Manager\\Power",
        "ControlSet001\\Control\\Session Manager\\AppCompatCache",
        "ControlSet001\\Control\\Session Manager\\KnownDLLs",
        "ControlSet001\\Control\\Session Manager\\FileRenameOperations",
        "ControlSet001\\Control\\Session Manager\\NamespaceSeparation",
        "ControlSet001\\Control\\Session Manager\\WPA",
        "ControlSet001\\Control\\Session Manager\\ApiSetSchemaExtensions",
    ]
    
    for path in sm_paths:
        key_name = path.split("\\")[-1]
        print(f"\n  Parsing: {key_name}")
        data = parse_subkey_recursive(reg, path, max_depth=2)
        if data:
            results[key_name] = data
            # Print key values
            for k, v in data.get("_values", {}).items():
                vstr = str(v)
                if len(vstr) > 120:
                    vstr = vstr[:120] + "..."
                print(f"    {k} = {vstr}")
            # Print subkey count
            sk_count = len(data.get("_subkeys", {}))
            if sk_count:
                print(f"    [{sk_count} subkeys]")
        else:
            results[key_name] = None
            print(f"    NOT FOUND")
    
    with open(os.path.join(OUTPUT_DIR, "session_manager_deep.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_control_set_deep():
    """Parse critical ControlSet entries beyond Session Manager"""
    print("\n" + "="*60)
    print("DEEP DIVE: ControlSet Critical Keys")
    print("="*60)
    
    results = {}
    reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
    
    control_paths = [
        "ControlSet001\\Control\\FileSystem",
        "ControlSet001\\Control\\Nls",
        "ControlSet001\\Control\\ComputerName",
        "ControlSet001\\Control\\HiveList",
        "ControlSet001\\Control\\ServiceGroupOrder",
        "ControlSet001\\Control\\GroupOrderList",
        "ControlSet001\\Control\\BootVerificationProgram",
        "ControlSet001\\Control\\Windows",
        "ControlSet001\\Control\\Lsa",
        "ControlSet001\\Control\\SecurePipeServers",
        "ControlSet001\\Control\\Print",
        "ControlSet001\\Control\\Terminal Server",
        "ControlSet001\\Control\\DeviceGuard",
        "ControlSet001\\Control\\CI",
        "ControlSet001\\Control\\CodeIntegrity",
    ]
    
    for path in control_paths:
        key_name = path.split("\\")[-1]
        print(f"\n  Parsing: {key_name}")
        data = parse_subkey_recursive(reg, path, max_depth=2)
        if data:
            results[key_name] = data
            for k, v in data.get("_values", {}).items():
                vstr = str(v)
                if len(vstr) > 120:
                    vstr = vstr[:120] + "..."
                print(f"    {k} = {vstr}")
        else:
            results[key_name] = None
            print(f"    NOT FOUND")
    
    with open(os.path.join(OUTPUT_DIR, "controlset_deep.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_software_deep():
    """Deep dive into SOFTWARE hive critical paths"""
    print("\n" + "="*60)
    print("DEEP DIVE: SOFTWARE Hive Critical Paths")
    print("="*60)
    
    results = {}
    reg = Registry.Registry(os.path.join(HIVE_DIR, "SOFTWARE.hiv"))
    
    software_paths = [
        "Microsoft\\Windows NT\\CurrentVersion\\SubSystems",  # Win32 subsystem registration
        "Microsoft\\Windows NT\\CurrentVersion\\Drivers32",   # 32-bit driver mappings
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",    # Logon configuration
        "Microsoft\\Windows NT\\CurrentVersion\\Perflib",     # Performance counters
        "Microsoft\\Windows NT\\CurrentVersion\\AeDebug",     # Debug handler
        "Microsoft\\Windows NT\\CurrentVersion\\Compatibility32",  # Compat entries
        "Microsoft\\Windows NT\\CurrentVersion\\Console",     # Console configuration
        "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "Microsoft\\Windows\\CurrentVersion\\App Paths",
        "Microsoft\\Windows\\CurrentVersion\\SideBySide",
        "Microsoft\\Windows\\CurrentVersion\\SharedDLLs",
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedDLLs",
        "Microsoft\\Cryptography\\Defaults\\Provider",
        "Microsoft\\Cryptography\\Defaults\\Provider Types",
        "Microsoft\\Cryptography\\OID",
        "Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes",
        "Microsoft\\Windows NT\\CurrentVersion\\Fonts",
        "Microsoft\\Windows NT\\CurrentVersion\\Gre_Initialize",
        "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        "Microsoft\\Windows NT\\CurrentVersion\\SeCEdit",
    ]
    
    for path in software_paths:
        key_name = path.replace("\\", "/").split("/")[-1]
        print(f"\n  Parsing: {key_name}")
        try:
            data = parse_subkey_recursive(reg, path, max_depth=2)
            if data:
                results[key_name] = data
                val_count = len(data.get("_values", {}))
                sk_count = len(data.get("_subkeys", {}))
                print(f"    {val_count} values, {sk_count} subkeys")
                # Print first few values
                for k, v in list(data.get("_values", {}).items())[:10]:
                    vstr = str(v)
                    if len(vstr) > 100:
                        vstr = vstr[:100] + "..."
                    print(f"    {k} = {vstr}")
            else:
                results[key_name] = None
                print(f"    NOT FOUND")
        except Exception as e:
            results[key_name] = f"ERROR: {e}"
            print(f"    ERROR: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "software_deep.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_apiset_schema():
    """
    The ApiSetMap is NOT stored in the registry in offline hives.
    It's built dynamically by the kernel from apisetchema.dll.
    However, we can find the schema extensions in the Session Manager.
    Let's also check if there's any API set related data in the SYSTEM hive.
    """
    print("\n" + "="*60)
    print("DEEP DIVE: API Set Schema (from Session Manager)")
    print("="*60)
    
    results = {}
    reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
    
    # Check ApiSetSchemaExtensions
    try:
        key = reg.open("ControlSet001\\Control\\Session Manager\\ApiSetSchemaExtensions")
        for val in key.values():
            results[val.name()] = safe_value(val.value())
        for subkey in key.subkeys():
            sk_data = {}
            for val in subkey.values():
                sk_data[val.name()] = safe_value(val.value())
            results[subkey.name()] = sk_data
        print(f"  ApiSetSchemaExtensions: {list(results.keys())}")
    except Exception as e:
        print(f"  ApiSetSchemaExtensions not found: {e}")
    
    # Search for any ApiSet related keys in the entire SYSTEM hive
    print("\n  Searching for API Set related keys in SYSTEM hive...")
    root = reg.open("ControlSet001\\Control")
    api_related = []
    
    for subkey in root.subkeys():
        name = subkey.name().lower()
        if 'api' in name or 'set' in name or 'schema' in name:
            api_related.append(subkey.name())
            print(f"    Found: ControlSet001\\Control\\{subkey.name()}")
    
    results["_api_related_in_control"] = api_related
    
    # Also check the full SYSTEM hive root for API sets
    try:
        root = reg.open("ControlSet001")
        for subkey in root.subkeys():
            name = subkey.name().lower()
            if 'api' in name:
                print(f"    Found: ControlSet001\\{subkey.name()}")
                api_related.append(f"ControlSet001\\{subkey.name()}")
    except:
        pass
    
    with open(os.path.join(OUTPUT_DIR, "apiset_schema.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_boot_drivers_detail():
    """Detailed analysis of boot drivers - what POLER-OS needs at startup"""
    print("\n" + "="*60)
    print("DEEP DIVE: Boot Drivers Detail")
    print("="*60)
    
    results = {"boot_drivers": [], "system_drivers": [], "driver_groups": {}}
    reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
    
    SERVICE_TYPES = {
        1: "KERNEL_DRIVER",
        2: "FILE_SYSTEM_DRIVER",
        16: "OWN_PROCESS",
        32: "SHARE_PROCESS",
    }
    
    try:
        key = reg.open("ControlSet001\\Services")
        for subkey in key.subkeys():
            info = {"name": subkey.name()}
            for val in subkey.values():
                info[val.name()] = safe_value(val.value())
            
            start = info.get("Start", -1)
            if isinstance(start, int) and start in (0, 1):  # BOOT or SYSTEM
                svc_type = info.get("Type", -1)
                group = info.get("Group", "")
                image_path = info.get("ImagePath", "")
                
                entry = {
                    "name": info["name"],
                    "type": SERVICE_TYPES.get(svc_type, f"TYPE_{svc_type}"),
                    "start": "BOOT" if start == 0 else "SYSTEM",
                    "group": group,
                    "image_path": image_path,
                }
                
                if start == 0:
                    results["boot_drivers"].append(entry)
                else:
                    results["system_drivers"].append(entry)
                
                if group:
                    if group not in results["driver_groups"]:
                        results["driver_groups"][group] = []
                    results["driver_groups"][group].append(info["name"])
        
        print(f"  Boot drivers (Start=0): {len(results['boot_drivers'])}")
        print(f"  System drivers (Start=1): {len(results['system_drivers'])}")
        print(f"  Driver groups: {len(results['driver_groups'])}")
        
        # Print boot drivers by group
        print("\n  Boot drivers by group:")
        for group in sorted(results["driver_groups"].keys()):
            drivers = results["driver_groups"][group]
            boot_drivers = [d for d in results["boot_drivers"] if d["group"] == group]
            if boot_drivers:
                print(f"    [{group}]: {', '.join(d['name'] for d in boot_drivers)}")
        
    except Exception as e:
        print(f"  Error: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "boot_drivers_detail.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def parse_service_group_order():
    """Parse the ServiceGroupOrder - critical for boot sequence"""
    print("\n" + "="*60)
    print("DEEP DIVE: Service Group Order (Boot Sequence)")
    print("="*60)
    
    results = {}
    reg = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
    
    try:
        key = reg.open("ControlSet001\\Control\\ServiceGroupOrder")
        for val in key.values():
            results[val.name()] = safe_value(val.value())
        
        # The "List" value contains the ordered list of driver groups
        if "List" in results:
            print(f"  Service group order (List): {len(results['List'])} groups")
            for i, group in enumerate(results["List"]):
                print(f"    {i+1}. {group}")
    except Exception as e:
        print(f"  Error: {e}")
    
    try:
        key = reg.open("ControlSet001\\Control\\GroupOrderList")
        for val in key.values():
            results[f"GroupOrderList/{val.name()}"] = safe_value(val.value())
    except Exception as e:
        print(f"  GroupOrderList: {e}")
    
    with open(os.path.join(OUTPUT_DIR, "service_group_order.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    return results


def main():
    print("="*60)
    print("POLER-OS: Deep Registry Analysis Part 2")
    print("="*60)
    
    results = {}
    results["session_manager"] = parse_session_manager_deep()
    results["control_set"] = parse_control_set_deep()
    results["software"] = parse_software_deep()
    results["apiset_schema"] = parse_apiset_schema()
    results["boot_drivers"] = parse_boot_drivers_detail()
    results["service_group_order"] = parse_service_group_order()
    
    print("\n" + "="*60)
    print("PART 2 ANALYSIS COMPLETE")
    print(f"Results: {OUTPUT_DIR}")
    print("="*60)


if __name__ == "__main__":
    main()
