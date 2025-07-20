#!/usr/bin/env python3
"""
File Integrity Monitor
A tool to monitor changes in files by calculating and comparing hash values.
"""

import hashlib
import os
import json
import time
from datetime import datetime
from pathlib import Path
import argparse
import sys


class FileIntegrityMonitor:
    def __init__(self, hash_algorithm='sha256'):
        """
        Initialize the file integrity monitor.
        
        Args:
            hash_algorithm (str): The hash algorithm to use (md5, sha1, sha256, sha512)
        """
        self.hash_algorithm = hash_algorithm
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if hash_algorithm not in self.hash_functions:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
        
        self.hash_file = 'file_hashes.json'
        self.stored_hashes = self.load_hashes()
    
    def calculate_file_hash(self, file_path):
        """
        Calculate the hash value of a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: Hexadecimal hash value
        """
        try:
            hash_func = self.hash_functions[self.hash_algorithm]()
            
            with open(file_path, 'rb') as file:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: file.read(4096), b""):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
        
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return None
        except PermissionError:
            print(f"Error: Permission denied accessing '{file_path}'.")
            return None
        except Exception as e:
            print(f"Error calculating hash for '{file_path}': {e}")
            return None
    
    def load_hashes(self):
        """
        Load previously stored hash values from JSON file.
        
        Returns:
            dict: Dictionary of file paths and their hash values
        """
        if os.path.exists(self.hash_file):
            try:
                with open(self.hash_file, 'r') as file:
                    return json.load(file)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load existing hash file: {e}")
                return {}
        return {}
    
    def save_hashes(self):
        """
        Save current hash values to JSON file.
        """
        try:
            with open(self.hash_file, 'w') as file:
                json.dump(self.stored_hashes, file, indent=2)
            print(f"Hash values saved to '{self.hash_file}'")
        except IOError as e:
            print(f"Error saving hash file: {e}")
    
    def scan_directory(self, directory_path, file_extensions=None):
        """
        Scan a directory and calculate hashes for all files.
        
        Args:
            directory_path (str): Path to the directory to scan
            file_extensions (list): List of file extensions to include (e.g., ['.txt', '.py'])
        
        Returns:
            dict: Dictionary of file paths and their hash values
        """
        if not os.path.exists(directory_path):
            print(f"Error: Directory '{directory_path}' does not exist.")
            return {}
        
        current_hashes = {}
        file_count = 0
        
        print(f"Scanning directory: {directory_path}")
        print(f"Hash algorithm: {self.hash_algorithm}")
        print("-" * 50)
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip if file extensions are specified and file doesn't match
                if file_extensions:
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext not in file_extensions:
                        continue
                
                # Skip the hash file itself
                if file_path == os.path.abspath(self.hash_file):
                    continue
                
                print(f"Processing: {file_path}")
                hash_value = self.calculate_file_hash(file_path)
                
                if hash_value:
                    current_hashes[file_path] = hash_value
                    file_count += 1
        
        print(f"\nProcessed {file_count} files")
        return current_hashes
    
    def compare_hashes(self, current_hashes):
        """
        Compare current hashes with stored hashes to detect changes.
        
        Args:
            current_hashes (dict): Current hash values
            
        Returns:
            tuple: (modified_files, new_files, deleted_files)
        """
        modified_files = []
        new_files = []
        deleted_files = []
        
        # Check for modified and new files
        for file_path, current_hash in current_hashes.items():
            if file_path in self.stored_hashes:
                if self.stored_hashes[file_path] != current_hash:
                    modified_files.append(file_path)
            else:
                new_files.append(file_path)
        
        # Check for deleted files
        for file_path in self.stored_hashes:
            if file_path not in current_hashes:
                deleted_files.append(file_path)
        
        return modified_files, new_files, deleted_files
    
    def monitor_files(self, directory_path, file_extensions=None, continuous=False, interval=5):
        """
        Monitor files for changes.
        
        Args:
            directory_path (str): Path to the directory to monitor
            file_extensions (list): List of file extensions to monitor
            continuous (bool): Whether to continuously monitor
            interval (int): Interval between checks in seconds (for continuous monitoring)
        """
        print("File Integrity Monitor")
        print("=" * 50)
        
        while True:
            current_hashes = self.scan_directory(directory_path, file_extensions)
            
            if not current_hashes:
                print("No files found to monitor.")
                return
            
            modified_files, new_files, deleted_files = self.compare_hashes(current_hashes)
            
            # Report changes
            if modified_files or new_files or deleted_files:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Changes detected:")
                
                if modified_files:
                    print(f"\nModified files ({len(modified_files)}):")
                    for file_path in modified_files:
                        print(f"  - {file_path}")
                
                if new_files:
                    print(f"\nNew files ({len(new_files)}):")
                    for file_path in new_files:
                        print(f"  + {file_path}")
                
                if deleted_files:
                    print(f"\nDeleted files ({len(deleted_files)}):")
                    for file_path in deleted_files:
                        print(f"  x {file_path}")
                
                # Update stored hashes
                self.stored_hashes.update(current_hashes)
                self.save_hashes()
                
            else:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No changes detected.")
            
            if not continuous:
                break
            
            print(f"\nWaiting {interval} seconds before next check...")
            time.sleep(interval)
    
    def create_baseline(self, directory_path, file_extensions=None):
        """
        Create a baseline of file hashes.
        
        Args:
            directory_path (str): Path to the directory
            file_extensions (list): List of file extensions to include
        """
        print("Creating baseline hash values...")
        current_hashes = self.scan_directory(directory_path, file_extensions)
        
        if current_hashes:
            self.stored_hashes = current_hashes
            self.save_hashes()
            print(f"Baseline created with {len(current_hashes)} files.")
        else:
            print("No files found to create baseline.")


def main():
    """Main function to handle command line arguments and run the monitor."""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor - Monitor file changes using hash values",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --directory /path/to/monitor --baseline
  python main.py --directory /path/to/monitor --monitor
  python main.py --directory /path/to/monitor --monitor --continuous --interval 10
  python main.py --directory /path/to/monitor --extensions .txt .py .md
        """
    )
    
    parser.add_argument(
        '--directory', '-d',
        required=True,
        help='Directory path to monitor'
    )
    
    parser.add_argument(
        '--baseline', '-b',
        action='store_true',
        help='Create baseline hash values'
    )
    
    parser.add_argument(
        '--monitor', '-m',
        action='store_true',
        help='Monitor files for changes'
    )
    
    parser.add_argument(
        '--continuous', '-c',
        action='store_true',
        help='Continuously monitor files'
    )
    
    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=5,
        help='Interval between checks in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--extensions', '-e',
        nargs='+',
        help='File extensions to monitor (e.g., .txt .py .md)'
    )
    
    parser.add_argument(
        '--algorithm', '-a',
        choices=['md5', 'sha1', 'sha256', 'sha512'],
        default='sha256',
        help='Hash algorithm to use (default: sha256)'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize the monitor
        monitor = FileIntegrityMonitor(args.algorithm)
        
        # Process file extensions
        file_extensions = None
        if args.extensions:
            file_extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' 
                             for ext in args.extensions]
        
        # Run based on arguments
        if args.baseline:
            monitor.create_baseline(args.directory, file_extensions)
        
        if args.monitor:
            monitor.monitor_files(
                args.directory,
                file_extensions,
                args.continuous,
                args.interval
            )
        
        if not args.baseline and not args.monitor:
            print("Please specify either --baseline or --monitor (or both)")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
