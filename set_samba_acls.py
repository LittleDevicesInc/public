#!/usr/bin/env python3
import csv
import subprocess
import os
from typing import Dict, List, Tuple

def read_csv_file(csv_path: str) -> Dict[str, List[Dict]]:
    """Read the CSV file and organize permissions by path"""
    permissions_by_path = {}

    with open(csv_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            path = row['Path'].strip('"')
            if path not in permissions_by_path:
                permissions_by_path[path] = []
            permissions_by_path[path].append(row)

    return permissions_by_path

def get_unique_paths(permissions: Dict[str, List[Dict]]) -> List[str]:
    """Get a list of unique base paths"""
    return sorted(list(permissions.keys()))

def convert_windows_path_to_samba(windows_path: str, base_samba_path: str = "/srv/vg0/d3da3351-2b94-4587-9863-a5d797c836fa/current") -> str:
    """Convert Windows path to Samba path"""
    # Remove drive letter and convert backslashes to forward slashes
    path = windows_path.split(':', 1)[1].replace('\\', '/')
    return os.path.join(base_samba_path, path.lstrip('/'))

def set_samba_acl(samba_path: str, principal: str, permissions: str, inheritance_flags: str, propagation_flags: str) -> None:
    """Set SAMBA ACL using samba-tool"""
    try:
        cmd = [
            'samba-tool', 'ntacl', 'set',
            f'--acl={principal}:{permissions}',
            f'--inheritance-flags={inheritance_flags}',
            f'--propagation-flags={propagation_flags}',
            samba_path
        ]
        subprocess.run(cmd, check=True)
        print(f"Successfully set ACL for {principal} on {samba_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error setting ACL: {e}")

def main():
    csv_path = "X-drive-permissions_20241130_153659.csv"

    # Read permissions from CSV
    permissions_by_path = read_csv_file(csv_path)
    unique_paths = get_unique_paths(permissions_by_path)

    # Display available paths
    print("\nAvailable shares:")
    for i, path in enumerate(unique_paths, 1):
        print(f"{i}. {path}")

    # Get user selection
    while True:
        try:
            selection = int(input("\nSelect a share number to process (or 0 to exit): "))
            if selection == 0:
                return
            if 1 <= selection <= len(unique_paths):
                break
            print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

    selected_path = unique_paths[selection - 1]
    samba_path = convert_windows_path_to_samba(selected_path)

    print(f"\nProcessing permissions for: {selected_path}")
    print(f"Samba path: {samba_path}")

    # Process permissions for selected path
    for perm in permissions_by_path[selected_path]:
        principal = perm['Group/User']
        windows_perms = perm['Permissions']
        inheritance = perm['InheritanceFlags']
        propagation = perm['PropagationFlags']

        # Convert Windows permissions to SAMBA format
        # This is a simplified conversion - you may need to adjust based on your needs
        samba_perms = "FULL" if "FullControl" in windows_perms else "READ"

        print(f"\nSetting permissions for {principal}:")
        print(f"Permissions: {windows_perms}")
        print(f"Inheritance: {inheritance}")
        print(f"Propagation: {propagation}")

        # Confirm before setting
        if input("Apply these permissions? (y/n): ").lower() == 'y':
            set_samba_acl(samba_path, principal, samba_perms, inheritance, propagation)
        else:
            print("Skipped.")

if __name__ == "__main__":
    main()