#!/usr/bin/env python3
"""Part 2 - Focused parsing of critical keys, no deep recursion on large hives"""

import os, json
from Registry import Registry

HIVE_DIR = "/home/z/my-project/registry-analysis/extracted/RegistryHives"
OUTPUT_DIR = "/home/z/my-project/registry-analysis/results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def safe_value(v):
    if isinstance(v, bytes):
        try: return v.decode('utf-16-le').rstrip('\x00')
        except:
            if len(v) <= 8: return int.from_bytes(v, 'little')
            return f"[bin:{len(v)}B]"
    elif isinstance(v, list): return [safe_value(x) for x in v]
    return str(v) if not isinstance(v, int) else v

def parse_flat(reg, path):
    """Parse only values of a key, no recursion"""
    try:
        key = reg.open(path)
        result = {}
        for val in key.values():
            result[val.name()] = safe_value(val.value())
        # List subkey names only
        result["_subkeys"] = [sk.name() for sk in key.subkeys()]
        return result
    except Exception as e:
        return {"_error": str(e)}

def main():
    results = {}
    
    # === SESSION MANAGER ===
    print("Parsing Session Manager subkeys...")
    reg_sys = Registry.Registry(os.path.join(HIVE_DIR, "SYSTEM.hiv"))
    
    sm_subkeys = [
        "ControlSet001\\Control\\Session Manager\\SubSystems",
        "ControlSet001\\Control\\Session Manager\\Memory Management",
        "ControlSet001\\Control\\Session Manager\\Executive",
        "ControlSet001\\Control\\Session Manager\\DOS Devices",
        "ControlSet001\\Control\\Session Manager\\Environment",
        "ControlSet001\\Control\\Session Manager\\I/O System",
        "ControlSet001\\Control\\Session Manager\\kernel",
        "ControlSet001\\Control\\Session Manager\\Power",
        "ControlSet001\\Control\\Session Manager\\KnownDLLs",
        "ControlSet001\\Control\\Session Manager\\NamespaceSeparation",
        "ControlSet001\\Control\\Session Manager\\WPA",
        "ControlSet001\\Control\\Session Manager\\ApiSetSchemaExtensions",
    ]
    
    for path in sm_subkeys:
        name = path.split("\\")[-1]
        data = parse_flat(reg_sys, path)
        results[f"SessionManager/{name}"] = data
        vals = {k:v for k,v in data.items() if not k.startswith("_")}
        print(f"  {name}: {len(vals)} values, {len(data.get('_subkeys',[]))} subkeys")
        for k,v in list(vals.items())[:5]:
            vs = str(v)[:80]
            print(f"    {k} = {vs}")
    
    # === SERVICE GROUP ORDER ===
    print("\nParsing Service Group Order...")
    sgo = parse_flat(reg_sys, "ControlSet001\\Control\\ServiceGroupOrder")
    results["ServiceGroupOrder"] = sgo
    if "List" in sgo:
        print(f"  Boot groups: {len(sgo['List'])}")
        for i, g in enumerate(sgo['List'][:20]):
            print(f"    {i+1}. {g}")
    
    # === CONTROL KEYS ===
    print("\nParsing Control keys...")
    control_keys = [
        "ControlSet001\\Control\\FileSystem",
        "ControlSet001\\Control\\Windows",
        "ControlSet001\\Control\\ComputerName\\ComputerName",
        "ControlSet001\\Control\\Lsa",
        "ControlSet001\\Control\\Nls\\CodePage",
        "ControlSet001\\Control\\DeviceGuard",
        "ControlSet001\\Control\\CI",
        "ControlSet001\\Control\\CodeIntegrity",
        "ControlSet001\\Control\\BootVerificationProgram",
        "ControlSet001\\Control\\HiveList",
    ]
    
    for path in control_keys:
        name = path.split("\\")[-1]
        data = parse_flat(reg_sys, path)
        results[f"Control/{name}"] = data
        vals = {k:v for k,v in data.items() if not k.startswith("_")}
        print(f"  {name}: {len(vals)} values")
        for k,v in list(vals.items())[:5]:
            vs = str(v)[:80]
            print(f"    {k} = {vs}")
    
    # === SOFTWARE - critical paths (flat) ===
    print("\nParsing SOFTWARE hive critical paths...")
    reg_sw = Registry.Registry(os.path.join(HIVE_DIR, "SOFTWARE.hiv"))
    
    sw_paths = [
        "Microsoft\\Windows NT\\CurrentVersion\\SubSystems",
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        "Microsoft\\Windows NT\\CurrentVersion\\Fonts",
        "Microsoft\\Cryptography\\Defaults\\Provider",
        "Microsoft\\Cryptography\\Defaults\\Provider Types",
    ]
    
    for path in sw_paths:
        name = path.split("\\")[-1]
        data = parse_flat(reg_sw, path)
        results[f"Software/{name}"] = data
        vals = {k:v for k,v in data.items() if not k.startswith("_")}
        sks = data.get('_subkeys', [])
        print(f"  {name}: {len(vals)} values, {len(sks)} subkeys")
        for k,v in list(vals.items())[:5]:
            vs = str(v)[:80]
            print(f"    {k} = {vs}")
        # Print subkey names for Provider types
        if name in ("Provider", "Provider Types") and sks:
            print(f"    Subkeys: {sks[:10]}")
    
    # === BOOT DRIVERS DETAIL ===
    print("\nParsing Boot/System drivers...")
    key = reg_sys.open("ControlSet001\\Services")
    boot_drivers = []
    system_drivers = []
    driver_groups = {}
    
    for subkey in key.subkeys():
        info = {"name": subkey.name()}
        for val in subkey.values():
            info[val.name()] = safe_value(val.value())
        
        start = info.get("Start", -1)
        if isinstance(start, int) and start in (0, 1):
            entry = {
                "name": info["name"],
                "type": info.get("Type", -1),
                "start": start,
                "group": info.get("Group", ""),
                "image_path": info.get("ImagePath", ""),
            }
            if start == 0:
                boot_drivers.append(entry)
            else:
                system_drivers.append(entry)
            
            group = info.get("Group", "")
            if group:
                driver_groups.setdefault(group, []).append(info["name"])
    
    results["boot_drivers"] = boot_drivers
    results["system_drivers"] = system_drivers
    
    print(f"  Boot (Start=0): {len(boot_drivers)}")
    print(f"  System (Start=1): {len(system_drivers)}")
    
    # Print boot drivers by group in order
    sgo_list = sgo.get("List", [])
    print("\n  Boot sequence by ServiceGroupOrder:")
    for group in sgo_list:
        drivers = driver_groups.get(group, [])
        boot_in_group = [d for d in drivers if d in [b["name"] for b in boot_drivers]]
        if boot_in_group:
            print(f"    [{group}]: {', '.join(boot_in_group)}")
    
    # Save
    with open(os.path.join(OUTPUT_DIR, "deep_analysis_p2.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\nResults saved to {OUTPUT_DIR}/deep_analysis_p2.json")

if __name__ == "__main__":
    main()
