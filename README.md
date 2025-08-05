# Disk Space Analyzer and Duplicate File Finder

A comprehensive Python script to analyze disk usage and identify potential duplicate files on your system.

## Features

- 🔍 **Drive Scanning**: Automatically detects and scans all available drives
- 📊 **Large File Detection**: Identifies the largest files consuming disk space
- 🔄 **Duplicate Detection**: Finds duplicate files using MD5 hash comparison
- 💾 **Space Analysis**: Calculates potential space savings from removing duplicates
- ⚡ **Performance**: Efficient scanning with progress indicators
- 🛡️ **Safe**: Read-only analysis - never modifies or deletes files

## Installation

1. Install Python 3.6 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage
```bash
python disk_analyzer.py
```
This will scan all available drives and show the top 50 largest files plus duplicate analysis.

### Advanced Options

```bash
# Scan specific drives only
python disk_analyzer.py --drives C: D:

# Change minimum file size threshold (default: 1MB)
python disk_analyzer.py --min-size 10

# Show more largest files
python disk_analyzer.py --top-files 100

# Skip duplicate detection for faster scanning
python disk_analyzer.py --no-duplicates

# Combine options
python disk_analyzer.py --drives C: --min-size 5 --top-files 25
```

### Command Line Arguments

- `--drives`: Specify which drives to scan (e.g., `C:` `D:`)
- `--min-size`: Minimum file size in MB to consider (default: 1)
- `--top-files`: Number of largest files to display (default: 50)
- `--no-duplicates`: Skip duplicate file detection

## Output

The script provides:

1. **Scan Summary**: Total files scanned, data processed, and scan time
2. **Largest Files**: Top N largest files with sizes and paths
3. **Duplicate Analysis**: 
   - Number of duplicate file groups found
   - Potential space savings
   - Detailed list of duplicate files grouped by size impact

## Safety Notes

- This script is **read-only** and will never delete or modify files
- It may take time to scan large drives (progress is shown)
- Some system directories are automatically skipped for safety
- Files smaller than 10MB are not checked for duplicates (performance optimization)

## Example Output

```
Starting disk analysis...
Minimum file size: 1 MB
Drives to scan: C:\, D:\
------------------------------------------------------------

Scanning drive: C:\
Scanned 5,000 files... Currently processing: C:\Users\...
Scanned 10,000 files... Currently processing: C:\Program Files\...

============================================================
SCAN COMPLETE
============================================================
Files scanned: 45,234
Total data scanned: 234.56 GB
Scan time: 45.23 seconds

📊 TOP 50 LARGEST FILES:
------------------------------------------------------------
 1.   4.56 GB - C:\Users\user\Videos\movie.mp4
 2.   2.34 GB - C:\Program Files\Game\data.pak
 3.   1.89 GB - C:\Users\user\Documents\backup.zip

🔍 DUPLICATE FILES ANALYSIS:
------------------------------------------------------------
Found 12 sets of duplicate files
Potential space savings: 3.45 GB

Top duplicate groups (by space waste):
1. 1.23 GB waste (3 copies of 615.00 MB file):
   - C:\Users\user\Downloads\video1.mp4
   - C:\Users\user\Desktop\video1.mp4
   - C:\Users\user\Videos\video1.mp4
```

## Performance Tips

- For faster scans, use `--min-size` to increase the minimum file size
- Use `--no-duplicates` to skip hash calculation if you only need size analysis
- Scan specific drives with `--drives` instead of all drives

## Troubleshooting

- **Permission Errors**: Run as administrator if you get permission denied errors
- **Slow Performance**: Increase `--min-size` or use `--no-duplicates`
- **Memory Usage**: The script uses minimal memory by processing files one at a time

## License

This script is provided as-is for personal use. Use at your own discretion.
