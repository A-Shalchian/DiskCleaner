import os

FILE_CATEGORIES = {
    'All Files': None,
    'Videos': {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpeg', '.mpg', '.3gp'},
    'Images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.svg', '.ico', '.raw', '.heic', '.heif'},
    'Audio': {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus', '.aiff'},
    'Documents': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.odt', '.ods', '.odp', '.csv'},
    'Archives': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.cab'},
    'Executables': {'.exe', '.msi', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.app', '.dmg'},
    'Code': {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rs', '.php', '.rb', '.swift', '.kt', '.html', '.css', '.json', '.xml', '.yaml', '.yml'},
    'Databases': {'.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.sql'},
    'Disk Images': {'.iso', '.img', '.vhd', '.vhdx', '.vmdk', '.qcow2'},
}

def get_file_category(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    for category, extensions in FILE_CATEGORIES.items():
        if extensions and ext in extensions:
            return category
    return 'Other'
