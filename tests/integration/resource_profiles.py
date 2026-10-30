"""Resource-profile evidence; no filesystem, Docker, or network side effects.

The disk declaration is operator evidence of a virtual disk's nominal size.
statvfs records a filesystem capacity separately; neither proves physical NVMe.
"""

import re

GIB = 1024**3
PROFILE_NAMES = ("legacy-8g", "competition-4g")
HOST_ONLINE_MEMORY_SOURCE = "local_linux_lsmem_online_ranges"


def online_memory_from_lsmem(payload):
    """Count distinct online physical ranges from lsmem --json --bytes."""
    if type(payload) is not dict or type(payload.get("memory")) is not list:
        raise ValueError("lsmem did not report a memory-range list")
    ranges = []
    for item in payload["memory"]:
        if type(item) is not dict:
            raise ValueError("invalid memory range record")
        if str(item.get("state", "")).lower() != "online":
            continue
        value = item.get("size")
        if type(value) is str and value.isdecimal():
            value = int(value)
        match = re.fullmatch(r"(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+)", str(item.get("range", "")))
        if type(value) is not int or value <= 0 or match is None:
            raise ValueError("invalid online memory range")
        start, end = (int(part, 16) for part in match.groups())
        if end < start or end - start + 1 != value:
            raise ValueError("online memory size does not match its physical range")
        ranges.append((start, end, value))
    ranges.sort()
    if not ranges or any(current[0] <= previous[1] for previous, current in zip(ranges, ranges[1:])):
        raise ValueError("missing or overlapping online memory ranges")
    total = sum(item[2] for item in ranges)
    if total > 2**64 - 1:
        raise ValueError("online memory size exceeds supported range")
    return total


def memory_match(info, profile, physical_memory_bytes=None, physical_memory_source=None):
    memory = info.get("MemTotal")
    if type(memory) is not int or memory <= 0:
        return "unknown", "docker_usable_memory"
    physical_known = (type(physical_memory_bytes) is int and physical_memory_bytes > 0
                      and physical_memory_source == HOST_ONLINE_MEMORY_SOURCE)
    if profile == "competition-4g" and physical_known:
        # MemTotal excludes reserved kernel/crashkernel memory. Keep the 4-GiB
        # physical requirement, and impose a separate useful-memory floor.
        matches = (3.5 * GIB <= physical_memory_bytes <= 4.5 * GIB
                   and 3 * GIB <= memory <= 4.5 * GIB and memory <= physical_memory_bytes)
        return "match" if matches else "mismatch", "host_online_physical_with_usable_guard"
    lower, upper = (7.5, 8.5) if profile == "legacy-8g" else (3.5, 4.5)
    return "match" if lower * GIB <= memory <= upper * GIB else "mismatch", "docker_usable_memory"


def hardware_matches(info, profile="legacy-8g", *, physical_memory_bytes=None, physical_memory_source=None):
    """Keep the historical CPU/RAM-only match distinct from host acceptance."""
    if profile not in PROFILE_NAMES:
        raise ValueError("unknown resource profile")
    cpu = info.get("NCPU")
    memory, _ = memory_match(info, profile, physical_memory_bytes, physical_memory_source)
    return type(cpu) is int and cpu == 4 and memory == "match"


def assess_resource_profile(info, profile="legacy-8g", *, dedicated_host_attested=False,
                            configured_disk_gb=None, filesystem_capacity=None,
                            physical_memory_bytes=None, physical_memory_source=None):
    if profile not in PROFILE_NAMES:
        raise ValueError("unknown resource profile")
    if configured_disk_gb is not None and (type(configured_disk_gb) is not int or configured_disk_gb <= 0):
        raise ValueError("configured disk size must be a positive nominal GB value")
    lower, upper = (7.5, 8.5) if profile == "legacy-8g" else (3.5, 4.5)
    cpu, memory = info.get("NCPU"), info.get("MemTotal")
    os_type, architecture = info.get("OSType"), info.get("Architecture")
    operating_system = str(info.get("OperatingSystem") or "").lower()
    desktop = any(name in operating_system for name in ("orbstack", "docker desktop"))
    ram_state, memory_basis = memory_match(info, profile, physical_memory_bytes, physical_memory_source)
    checks = {
        "cpu": "unknown" if type(cpu) is not int or cpu <= 0 else "match" if cpu == 4 else "mismatch",
        "ram": ram_state,
        "linux_amd64": "unknown" if not os_type or not architecture else "match" if str(os_type).lower() == "linux" and str(architecture).lower() in ("amd64", "x86_64") else "mismatch",
        "native_docker_host": "mismatch" if desktop else "match" if operating_system else "unknown",
        "dedicated_host": "match" if dedicated_host_attested is True else "unknown",
    }
    if profile == "competition-4g":
        checks["configured_virtual_disk"] = "unknown" if configured_disk_gb is None else "match" if configured_disk_gb == 40 else "mismatch"
        capacity = filesystem_capacity if type(filesystem_capacity) is dict else {}
        total, available = capacity.get("total_bytes"), capacity.get("available_bytes")
        checks["filesystem_capacity_recorded"] = (
            "match" if type(total) is int and total > 0 and type(available) is int
            and 0 <= available <= total and str(capacity.get("path", "")).startswith("/")
            else "unknown")
    mismatches = [name for name, state in checks.items() if state == "mismatch"]
    unknown = [name for name, state in checks.items() if state == "unknown"]
    state = "mismatch" if mismatches else "unknown" if unknown else "match"
    return {
        "id": profile,
        "state": state,
        "host_match": state == "match",
        "checks": checks,
        "mismatches": mismatches,
        "unknown": unknown,
        "expected": {"os": "linux", "architecture": "amd64", "cpu_count": 4,
                     "memory_min_bytes": int(lower * GIB), "memory_max_bytes": int(upper * GIB),
                     "memory_range_applies_to": "measured_online_physical_else_Docker_MemTotal" if profile == "competition-4g" else "Docker_MemTotal",
                     "usable_memory_min_with_physical_evidence_bytes": 3 * GIB if profile == "competition-4g" else None,
                     "configured_virtual_disk_gb": 40 if profile == "competition-4g" else None},
        "observed": {"os": os_type, "architecture": architecture, "cpu_count": cpu,
                     "memory_total_bytes": memory, "physical_online_memory_bytes": physical_memory_bytes,
                     "physical_memory_source": physical_memory_source, "operating_system": info.get("OperatingSystem")},
        "memory_basis": memory_basis,
        "online_minus_memtotal_bytes": (physical_memory_bytes - memory if type(physical_memory_bytes) is int
                                       and type(memory) is int and physical_memory_bytes >= memory else None),
        "dedicated_host_attested": dedicated_host_attested is True,
        "configured_virtual_disk_gb": configured_disk_gb,
        "disk_declaration_source": "operator_cli_nominal_virtual_disk_size" if configured_disk_gb is not None else "unconfigured",
        "filesystem_capacity": filesystem_capacity,
        "filesystem_capacity_is_virtual_disk_size": False,
        "physical_nvme_verified": False,
    }


def acceptance_fields(profile_observation, measurement_status):
    """A 4-GiB pass must never become a legacy 8-GiB reference pass."""
    passed = profile_observation["host_match"] and measurement_status == "passed"
    return {
        "resource_profile_acceptance": "passed" if passed else "not_claimed",
        "reference_acceptance": "passed" if passed and profile_observation["id"] == "legacy-8g" else "not_claimed",
        "competition_acceptance": "passed" if passed and profile_observation["id"] == "competition-4g" else "not_claimed",
    }
