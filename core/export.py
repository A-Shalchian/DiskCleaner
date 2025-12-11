import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Any

from .utils import format_size
from .categories import get_file_category


def export_large_files_csv(filepath: str, large_files: List[tuple], format_size_func=None):
    if format_size_func is None:
        format_size_func = format_size

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['rank', 'size', 'size_bytes', 'path', 'category', 'filename'])
        writer.writeheader()
        for rank, (size_bytes, path) in enumerate(large_files, 1):
            writer.writerow({
                'rank': rank,
                'size': format_size_func(size_bytes) if isinstance(size_bytes, int) else size_bytes,
                'size_bytes': size_bytes if isinstance(size_bytes, int) else 0,
                'path': path,
                'category': get_file_category(path),
                'filename': os.path.basename(path)
            })


def export_large_files_json(filepath: str, large_files: List[tuple], format_size_func=None):
    if format_size_func is None:
        format_size_func = format_size

    export_data = []
    for rank, (size_bytes, path) in enumerate(large_files, 1):
        export_data.append({
            'rank': rank,
            'size': format_size_func(size_bytes) if isinstance(size_bytes, int) else size_bytes,
            'size_bytes': size_bytes if isinstance(size_bytes, int) else 0,
            'path': path,
            'category': get_file_category(path),
            'filename': os.path.basename(path)
        })

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            'export_type': 'large_files',
            'export_date': datetime.now().isoformat(),
            'total_files': len(export_data),
            'files': export_data
        }, f, indent=2, ensure_ascii=False)


def export_large_files_txt(filepath: str, large_files: List[tuple], format_size_func=None):
    if format_size_func is None:
        format_size_func = format_size

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("LARGE FILES REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Files: {len(large_files)}\n")
        f.write("=" * 80 + "\n\n")

        for rank, (size_bytes, path) in enumerate(large_files, 1):
            size = format_size_func(size_bytes) if isinstance(size_bytes, int) else size_bytes
            category = get_file_category(path)
            f.write(f"{rank:4d}. [{category:12s}] {size:>12s}  {path}\n")

        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")


def export_duplicates_csv(filepath: str, duplicates: Dict[str, List[str]], format_size_func=None):
    if format_size_func is None:
        format_size_func = format_size

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['group', 'size', 'size_bytes', 'copies', 'waste', 'path', 'filename'])
        writer.writeheader()

        for group_num, (file_hash, filepaths) in enumerate(duplicates.items(), 1):
            if len(filepaths) <= 1:
                continue
            try:
                size_bytes = os.path.getsize(filepaths[0])
                waste = (len(filepaths) - 1) * size_bytes
            except OSError:
                size_bytes = 0
                waste = 0

            for path in filepaths:
                writer.writerow({
                    'group': group_num,
                    'size': format_size_func(size_bytes),
                    'size_bytes': size_bytes,
                    'copies': len(filepaths),
                    'waste': format_size_func(waste),
                    'path': path,
                    'filename': os.path.basename(path)
                })


def export_duplicates_json(filepath: str, duplicates: Dict[str, List[str]], format_size_func=None):
    if format_size_func is None:
        format_size_func = format_size

    groups = []
    total_waste = 0

    for group_num, (file_hash, filepaths) in enumerate(duplicates.items(), 1):
        if len(filepaths) <= 1:
            continue
        try:
            size_bytes = os.path.getsize(filepaths[0])
            waste = (len(filepaths) - 1) * size_bytes
            total_waste += waste
        except OSError:
            size_bytes = 0
            waste = 0

        groups.append({
            'group': group_num,
            'size': format_size_func(size_bytes),
            'size_bytes': size_bytes,
            'copies': len(filepaths),
            'waste': format_size_func(waste),
            'waste_bytes': waste,
            'files': filepaths
        })

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            'export_type': 'duplicates',
            'export_date': datetime.now().isoformat(),
            'total_groups': len(groups),
            'total_waste': format_size_func(total_waste),
            'total_waste_bytes': total_waste,
            'groups': groups
        }, f, indent=2, ensure_ascii=False)


def export_duplicates_txt(filepath: str, duplicates: Dict[str, List[str]], format_size_func=None):
    if format_size_func is None:
        format_size_func = format_size

    total_waste = 0
    groups_data = []

    for group_num, (file_hash, filepaths) in enumerate(duplicates.items(), 1):
        if len(filepaths) <= 1:
            continue
        try:
            size_bytes = os.path.getsize(filepaths[0])
            waste = (len(filepaths) - 1) * size_bytes
            total_waste += waste
        except OSError:
            size_bytes = 0
            waste = 0
        groups_data.append((group_num, size_bytes, waste, filepaths))

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("DUPLICATE FILES REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Duplicate Groups: {len(groups_data)}\n")
        f.write(f"Potential Space Savings: {format_size_func(total_waste)}\n")
        f.write("=" * 80 + "\n\n")

        for group_num, size_bytes, waste, filepaths in groups_data:
            f.write(f"Group #{group_num} - {len(filepaths)} copies of {format_size_func(size_bytes)} file (waste: {format_size_func(waste)})\n")
            f.write("-" * 60 + "\n")
            for path in filepaths:
                f.write(f"  - {path}\n")
            f.write("\n")

        f.write("=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")
