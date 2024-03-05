#! /usr/bin/python
import platform

def get_os_details():
    details = {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }
    return details

if __name__ == "__main__":
    os_details = get_os_details()
    for key, value in os_details.items():
        print(f"{key}: {value}")