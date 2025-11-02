# Disk Space Analyzer & Duplicate File Finder

A disk space analyzer that helps you find large files and duplicates on your system. I built this because I was tired of running out of space and not knowing where it all went.

## Screenshot

![Disk Cleaner - Electron.js Version](Disk_Cleaner.png)

*Electron.js version with a modern UI*

## What's in here

- `disk_analyzer.py` - Command line version with parallel scanning
- `disk_cleaner_gui.py` - GUI version with a proper interface
- `main.py` - Entry point that launches the GUI
- `requirements.txt` - Just psutil for now

## Getting started

You need Python 3.7 or newer. Install the dependency:

```bash
pip install -r requirements.txt
```

Then run whichever version you prefer:

```bash
# GUI version (recommended)
python main.py

# Command line version
python disk_analyzer.py

# Command line with options
python disk_analyzer.py --drives C: --min-size 10
```

## Command line options

If you're using the CLI version, here are the options:

- `--drives C: D:` - Scan specific drives instead of all of them
- `--min-size 10` - Only look at files larger than 10MB (default is 1MB)
- `--top-files 100` - Show top 100 files instead of default 50
- `--no-duplicates` - Skip duplicate detection if you just want to see large files

## How it works

The scanner walks through your drives and catalogs files. For duplicate detection, it uses a two-stage approach: first a fast hash based on file size and samples from the beginning and end of the file, then a full hash verification for anything that might be a duplicate. This makes it much faster than hashing every file completely.

The GUI version shows you three tabs:

1. Largest Files - sorted list of your biggest files
2. Duplicate Files - groups of identical files that are wasting space
3. Delete Commands - batch scripts you can review and run to clean things up

## Safety stuff

The scanning process is read-only. It won't delete or modify anything during the scan. If you want to delete duplicates, the GUI generates batch scripts that you can review first. The scripts always keep the first copy and only delete the extras.

That said, be careful. Review what you're deleting. I'm not responsible if you delete something important.

## Performance notes

The scanner uses multiple threads when scanning multiple drives. It skips system directories like Windows, Program Files, and recycle bins to avoid permission issues and speed things up. On a typical system you should see around 3000-5000 files per second depending on your drive speed.

Files smaller than 5MB are tracked but not checked for duplicates by default since they usually don't contribute much to space issues.

## Limitations

- Only checks files above your minimum size threshold (default 1MB)
- Duplicate detection uses MD5 hashing (fast but not cryptographically secure - doesn't matter for this use case)
- Skips system directories automatically which might miss some duplicates
- GUI only opens first 3 duplicate locations to avoid overwhelming Windows Explorer

## Requirements

- Python 3.7 or later
- psutil library for drive detection
- tkinter (comes with Python on Windows and most Linux distros)
- Works on Windows, macOS, and Linux (though I've mostly tested on Windows)

## Contributing

Feel free to submit issues or pull requests if you find bugs or have ideas for improvements.
