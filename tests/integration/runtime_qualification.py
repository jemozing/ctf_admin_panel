"""Qualify observed guest/client architecture without physical-host claims."""

import platform


def normalize_architecture(value):
    value = str(value or "").lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)


def observed_platform(os_type, architecture):
    os_type = str(os_type or "").lower()
    architecture = normalize_architecture(architecture)
    return os_type + "/" + architecture if os_type and architecture else None


def runtime_qualification(server, image, *, binary_platform=None, client_system=None, client_machine=None):
    daemon = observed_platform(server.get("Os"), server.get("Arch"))
    image_platform = observed_platform(image.get("Os"), image.get("Architecture"))
    client = observed_platform(platform.system() if client_system is None else client_system,
                               platform.machine() if client_machine is None else client_machine)
    binary = None
    if isinstance(binary_platform, str) and binary_platform.count("/") == 1:
        binary = observed_platform(*binary_platform.split("/"))
    image_match = daemon == image_platform if daemon and image_platform else None
    binary_match = daemon == binary if daemon and binary else None
    execution = ("not_probed" if binary_match is None else
                 "matching_guest_architecture" if binary_match else "different_guest_architecture")
    return {
        "daemon_platform": daemon,
        "executor_image_platform": image_platform,
        "client_platform": client,
        "executor_binary_platform": binary,
        "image_matches_daemon": image_match,
        "executor_matches_daemon": binary_match,
        "guest_executor_execution": execution,
        "architecture_metadata_state": "unknown" if image_match is None else "match" if image_match else "mismatch",
        "physical_host_architecture_verified": False,
        "hypervisor_verified": False,
        "dedicated_host_verified": False,
        "physical_nvme_verified": False,
        "scope_note": ("Observed Docker daemon " + (daemon or "unknown") + ", executor image "
                       + (image_platform or "unknown") + ", client " + (client or "unknown")
                       + "; binary execution evidence is recorded separately. Matching guest architecture does not attest physical host, hypervisor, dedicated resources, or NVMe."),
    }
