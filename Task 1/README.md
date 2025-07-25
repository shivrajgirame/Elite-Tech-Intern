# File Integrity Monitor

A Python tool to monitor changes in files by calculating and comparing hash values using the `hashlib` library. This tool helps ensure file integrity by detecting modifications, additions, and deletions of files in a specified directory.

## Features

- **Multiple Hash Algorithms**: Support for MD5, SHA1, SHA256, and SHA512
- **Baseline Creation**: Create initial hash values for files
- **Change Detection**: Detect modified, new, and deleted files
- **Continuous Monitoring**: Monitor files continuously with configurable intervals
- **File Extension Filtering**: Monitor only specific file types
- **JSON Storage**: Store hash values in a JSON file for persistence
- **Error Handling**: Robust error handling for file access issues
- **Command Line Interface**: Easy-to-use command line interface

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library modules)

## Installation

1. Clone or download the `main.py` file
2. Make the script executable (optional):
   ```bash
   chmod +x main.py
   ```

## Usage

### Basic Commands

#### 1. Create a Baseline
Create initial hash values for all files in a directory:
```bash
python main.py --directory /path/to/monitor --baseline
```

#### 2. Monitor for Changes
Check for changes once:
```bash
python main.py --directory /path/to/monitor --monitor
```

#### 3. Continuous Monitoring
Monitor files continuously with 10-second intervals:
```bash
python main.py --directory /path/to/monitor --monitor --continuous --interval 10
```

#### 4. Monitor Specific File Types
Monitor only Python and text files:
```bash
python main.py --directory /path/to/monitor --monitor --extensions .py .txt
```

#### 5. Use Different Hash Algorithm
Use SHA512 instead of the default SHA256:
```bash
python main.py --directory /path/to/monitor --baseline --algorithm sha512
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--directory` | `-d` | Directory path to monitor (required) |
| `--baseline` | `-b` | Create baseline hash values |
| `--monitor` | `-m` | Monitor files for changes |
| `--continuous` | `-c` | Continuously monitor files |
| `--interval` | `-i` | Interval between checks in seconds (default: 5) |
| `--extensions` | `-e` | File extensions to monitor (e.g., .txt .py .md) |
| `--algorithm` | `-a` | Hash algorithm to use (md5, sha1, sha256, sha512) |

### Examples

#### Example 1: Monitor a Project Directory
```bash
# Create baseline for a Python project
python main.py --directory ./my_project --baseline --extensions .py .txt .md

# Monitor for changes
python main.py --directory ./my_project --monitor --extensions .py .txt .md
```

#### Example 2: Continuous Monitoring of Documents
```bash
# Monitor documents continuously every 30 seconds
python main.py --directory ~/Documents --monitor --continuous --interval 30 --extensions .doc .docx .pdf .txt
```

#### Example 3: High-Security Monitoring with SHA512
```bash
# Use SHA512 for maximum security
python main.py --directory /important/files --baseline --algorithm sha512
python main.py --directory /important/files --monitor --continuous --algorithm sha512
```

## Output

The tool provides detailed output showing:

- **Scanning Progress**: Shows which files are being processed
- **Change Detection**: Reports modified, new, and deleted files with timestamps
- **File Counts**: Shows how many files were processed
- **Error Messages**: Displays any errors encountered during file access

### Sample Output
```
File Integrity Monitor
==================================================
Scanning directory: /path/to/monitor
Hash algorithm: sha256
--------------------------------------------------
Processing: /path/to/monitor/file1.txt
Processing: /path/to/monitor/file2.py
Processing: /path/to/monitor/subdir/file3.md

Processed 3 files

[2024-01-15 14:30:25] Changes detected:

Modified files (1):
  - /path/to/monitor/file1.txt

New files (1):
  + /path/to/monitor/newfile.txt

Hash values saved to 'file_hashes.json'
```

## File Storage

The tool creates a `file_hashes.json` file in the current directory to store hash values. This file contains:

```json
{
  "/path/to/file1.txt": "a1b2c3d4e5f6...",
  "/path/to/file2.py": "f6e5d4c3b2a1...",
  "/path/to/subdir/file3.md": "1234567890ab..."
}
```

## Security Considerations

- **Hash Algorithms**: SHA256 is recommended for most use cases. SHA512 provides maximum security but is slower.
- **File Permissions**: Ensure the tool has read access to monitored directories.
- **Hash File**: The `file_hashes.json` file contains sensitive information and should be protected.

## Error Handling

The tool handles various error scenarios:

- **File Not Found**: Skips files that don't exist
- **Permission Denied**: Reports access permission issues
- **Corrupted Hash File**: Automatically recreates hash file if corrupted
- **Invalid Arguments**: Provides helpful error messages for incorrect usage

## Use Cases

1. **Code Repository Monitoring**: Detect unauthorized changes to source code
2. **Document Integrity**: Ensure important documents haven't been modified
3. **System File Monitoring**: Monitor critical system files for tampering
4. **Backup Verification**: Verify backup integrity
5. **Compliance Auditing**: Meet regulatory requirements for file integrity

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you have read access to the monitored directory
2. **No Files Found**: Check if the directory path is correct and contains files
3. **Hash File Corruption**: Delete `file_hashes.json` and recreate the baseline

### Performance Tips

- Use specific file extensions to reduce processing time
- Increase monitoring intervals for large directories
- Consider using MD5 for faster processing (less secure)

## License

This tool is provided as-is for educational and practical use. Feel free to modify and distribute as needed. 