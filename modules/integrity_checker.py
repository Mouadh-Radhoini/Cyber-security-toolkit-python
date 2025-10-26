import hashlib
import json
import os
from datetime import datetime


class FileIntegrityChecker:
    def __init__(self, directory):
        self.directory = directory
        self.baseline_file = 'data/hashes/baseline.json'

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                while chunk := f.read(65536):  # 64KB chunks
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"[-] Error hashing {file_path}: {str(e)}")
            return None

    def create_baseline(self):
        """Create baseline hashes for all files in directory"""
        print(f"\n[*] Creating baseline for: {self.directory}")

        baseline = {}
        file_count = 0

        # Walk through directory tree
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = self.calculate_file_hash(file_path)

                if file_hash:
                    # Store relative path as key
                    relative_path = os.path.relpath(file_path, self.directory)
                    baseline[relative_path] = {
                        'hash': file_hash,
                        'size': os.path.getsize(file_path),
                        'modified': os.path.getmtime(file_path)
                    }
                    file_count += 1
                    print(f"[+] Hashed: {relative_path}")

        # Save baseline to file
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)

        baseline_data = {
            'timestamp': str(datetime.now()),
            'directory': self.directory,
            'file_count': file_count,
            'hashes': baseline
        }

        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=4)

        print(f"\n[+] Baseline created successfully!")
        print(f"[+] Total files hashed: {file_count}")
        print(f"[+] Baseline saved to: {self.baseline_file}\n")

        return baseline

    def load_baseline(self):
        """Load baseline from file"""
        if not os.path.exists(self.baseline_file):
            print("[-] No baseline found! Create one first.")
            return None

        with open(self.baseline_file, 'r') as f:
            baseline_data = json.load(f)

        return baseline_data

    def verify_integrity(self):
        """Verify file integrity against baseline"""
        print(f"\n[*] Verifying integrity for: {self.directory}")

        baseline_data = self.load_baseline()
        if not baseline_data:
            return None

        baseline = baseline_data['hashes']

        print(f"[*] Baseline created: {baseline_data['timestamp']}")
        print(f"[*] Baseline file count: {baseline_data['file_count']}\n")

        modified_files = []
        added_files = []
        deleted_files = list(baseline.keys())
        current_files = {}

        # Scan current directory
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, self.directory)

                current_hash = self.calculate_file_hash(file_path)
                if not current_hash:
                    continue

                current_files[relative_path] = current_hash

                # Check if file existed in baseline
                if relative_path in baseline:
                    # Remove from deleted list (file still exists)
                    deleted_files.remove(relative_path)

                    # Check if modified
                    if current_hash != baseline[relative_path]['hash']:
                        modified_files.append(relative_path)
                        print(f"[!] MODIFIED: {relative_path}")
                else:
                    # New file added
                    added_files.append(relative_path)
                    print(f"[+] ADDED: {relative_path}")

        # Report results
        print(f"\n{'=' * 60}")
        print("INTEGRITY CHECK RESULTS")
        print(f"{'=' * 60}")

        if modified_files:
            print(f"\n[!] Modified Files ({len(modified_files)}):")
            for f in modified_files:
                print(f"    - {f}")

        if added_files:
            print(f"\n[+] Added Files ({len(added_files)}):")
            for f in added_files:
                print(f"    - {f}")

        if deleted_files:
            print(f"\n[-] Deleted Files ({len(deleted_files)}):")
            for f in deleted_files:
                print(f"    - {f}")

        if not modified_files and not added_files and not deleted_files:
            print("\n[+] No changes detected - All files match baseline!")

        print(f"\n{'=' * 60}\n")

        # Return summary
        return {
            'modified': modified_files,
            'added': added_files,
            'deleted': deleted_files
        }


# Usage example
if __name__ == "__main__":
    directory = "/path/to/monitor"
    checker = FileIntegrityChecker(directory)

    # Create baseline (run once)
    checker.create_baseline()

    # Verify integrity (run regularly)
    # results = checker.verify_integrity()
