// Disk Cleaner - Electron Renderer Process
let isScanning = false;
let currentTab = 'largeFiles';
let duplicateData = {};
let currentTheme = 'light';

// Initialize on load
document.addEventListener('DOMContentLoaded', async () => {
    initializeTheme();
    await initializeApp();
    setupEventListeners();
    setupTabs();
    setupProgressListener();
});

// Theme Management
function initializeTheme() {
    const savedTheme = localStorage.getItem('diskCleanerTheme') || 'light';
    setTheme(savedTheme);
}

function setTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('diskCleanerTheme', theme);

    const themeIcon = document.getElementById('themeIcon');
    const themeText = document.getElementById('themeText');

    if (theme === 'dark') {
        themeIcon.textContent = '☀️';
        themeText.textContent = 'Light';
    } else {
        themeIcon.textContent = '🌙';
        themeText.textContent = 'Dark';
    }
}

function toggleTheme() {
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

// Initialize app
async function initializeApp() {
    // Get version from Electron
    try {
        const version = await window.electronAPI.getVersion();
        document.getElementById('version').textContent = `v${version}`;
    } catch (error) {
        console.error('Error getting version:', error);
        document.getElementById('version').textContent = 'v1.0.0';
    }

    // Load available drives
    await loadDrives();
}

async function loadDrives() {
    const drivesSelect = document.getElementById('drives');

    try {
        console.log('Loading drives...');
        const drives = await window.electronAPI.getDrives();
        console.log('Received drives:', drives);

        if (drives && Array.isArray(drives) && drives.length > 0) {
            drivesSelect.innerHTML = '<option value="all">All Drives</option>';
            drives.forEach(drive => {
                const option = document.createElement('option');
                option.value = drive;
                option.textContent = drive;
                drivesSelect.appendChild(option);
            });
            console.log('✓ Drives loaded successfully');
        } else {
            console.warn('No drives returned');
            drivesSelect.innerHTML = '<option value="all">All Drives</option>';
        }
    } catch (error) {
        console.error('Error loading drives:', error);
        drivesSelect.innerHTML = '<option value="all">All Drives</option>';
    }
}

function setupEventListeners() {
    // Theme toggle
    document.getElementById('themeToggle').addEventListener('click', toggleTheme);

    // Scan controls
    document.getElementById('startScan').addEventListener('click', startScan);
    document.getElementById('stopScan').addEventListener('click', stopScan);
    document.getElementById('clearResults').addEventListener('click', clearResults);

    // Duplicates
    document.getElementById('refreshDuplicates').addEventListener('click', refreshDuplicates);

    // Commands
    document.getElementById('saveCommands').addEventListener('click', saveCommands);
    document.getElementById('copyCommands').addEventListener('click', copyCommands);
    document.getElementById('clearCommands').addEventListener('click', clearCommands);

    // Context menu
    document.addEventListener('click', () => {
        document.getElementById('contextMenu').style.display = 'none';
    });
}

function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    let contentId;
    switch (tabName) {
        case 'largeFiles':
            contentId = 'largeFilesTab';
            break;
        case 'duplicates':
            contentId = 'duplicatesTab';
            break;
        case 'commands':
            contentId = 'commandsTab';
            break;
    }
    document.getElementById(contentId).classList.add('active');
    currentTab = tabName;
}

// Progress listener
function setupProgressListener() {
    window.electronAPI.onScanProgress((data) => {
        if (data.type === 'progress' || data.type === 'status') {
            updateProgress(data.message, true);
        }
    });
}

async function startScan() {
    if (isScanning) return;

    const drives = document.getElementById('drives').value;
    const minSize = parseInt(document.getElementById('minSize').value);

    if (isNaN(minSize) || minSize < 1) {
        alert('Please enter a valid minimum file size');
        return;
    }

    isScanning = true;
    updateScanningState(true);

    try {
        const results = await window.electronAPI.startScan(drives, minSize);

        if (!results.cancelled) {
            isScanning = false;
            updateScanningState(false);
            updateProgress(results.message, false);

            populateLargeFiles(results.largestFiles);
            populateDuplicates(results.duplicates);
        }
    } catch (error) {
        console.error('Error during scan:', error);
        updateProgress('Error during scan', false);
        isScanning = false;
        updateScanningState(false);
        alert(`Scan error: ${error.message}`);
    }
}

async function stopScan() {
    try {
        await window.electronAPI.stopScan();
        updateProgress('Stopping scan...', false);
        isScanning = false;
        updateScanningState(false);
    } catch (error) {
        console.error('Error stopping scan:', error);
    }
}

function updateScanningState(scanning) {
    document.getElementById('startScan').disabled = scanning;
    document.getElementById('stopScan').disabled = !scanning;

    const progressBar = document.getElementById('progressBar');
    if (scanning) {
        progressBar.classList.add('active');
    } else {
        progressBar.classList.remove('active');
    }
}

function updateProgress(message, isActive) {
    document.getElementById('progressText').textContent = message;
    const progressBar = document.getElementById('progressBar');
    if (isActive) {
        progressBar.classList.add('active');
    } else {
        progressBar.classList.remove('active');
    }
}

function populateLargeFiles(files) {
    const tbody = document.getElementById('largeFilesBody');
    tbody.innerHTML = '';

    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr class="empty-state"><td colspan="3">No large files found</td></tr>';
        return;
    }

    files.forEach(file => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${file.size}</td>
            <td title="${file.path}">${file.path}</td>
            <td>
                <button class="btn btn-small btn-secondary action-btn" onclick="openFileLocation('${escapeHtml(file.path)}')">
                    Open
                </button>
                <button class="btn btn-small btn-danger action-btn" onclick="deleteFile('${escapeHtml(file.path)}')">
                    Delete
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function populateDuplicates(duplicates) {
    const tbody = document.getElementById('duplicatesBody');
    tbody.innerHTML = '';

    if (!duplicates || duplicates.length === 0) {
        tbody.innerHTML = '<tr class="empty-state"><td colspan="6">No duplicates found</td></tr>';
        document.getElementById('duplicatesInfo').textContent = 'No duplicate files found';
        return;
    }

    const totalGroups = duplicates.length;
    const totalWaste = duplicates.reduce((sum, dup) => sum + dup.waste_bytes, 0);
    document.getElementById('duplicatesInfo').textContent =
        `Found ${totalGroups} duplicate groups, potential savings: ${formatBytes(totalWaste)}`;

    duplicates.forEach((dup, index) => {
        const groupId = `dup_${index}`;
        duplicateData[groupId] = dup.files;

        const row = document.createElement('tr');
        const filesPreview = dup.files.slice(0, 2).join(' | ') + (dup.files.length > 2 ? ` | ... (+${dup.files.length - 2} more)` : '');

        row.innerHTML = `
            <td>#${index + 1}</td>
            <td>${dup.count}</td>
            <td>${dup.size}</td>
            <td>${dup.waste}</td>
            <td title="${dup.files.join('\n')}">${filesPreview}</td>
            <td>
                <button class="btn btn-small btn-danger action-btn" onclick="deleteDuplicateGroup('${groupId}')">
                    Delete
                </button>
                <button class="btn btn-small btn-secondary action-btn" onclick="openDuplicateLocations('${groupId}')">
                    Open
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function refreshDuplicates() {
    updateProgress('Refreshing duplicates...', true);
    try {
        const results = await window.electronAPI.refreshDuplicates();
        updateProgress(results.message, false);
        populateDuplicates(results.duplicates);
    } catch (error) {
        console.error('Error refreshing duplicates:', error);
        updateProgress('Error refreshing duplicates', false);
    }
}

async function openFileLocation(filepath) {
    try {
        await window.electronAPI.openFileLocation(filepath);
    } catch (error) {
        console.error('Error opening file location:', error);
        alert('Could not open file location');
    }
}

async function deleteFile(filepath) {
    if (!confirm(`Are you sure you want to delete this file?\n\n${filepath}`)) {
        return;
    }

    try {
        const result = await window.electronAPI.deleteFile(filepath);
        if (result.success) {
            alert('File deleted successfully');
            const tbody = document.getElementById('largeFilesBody');
            const rows = tbody.querySelectorAll('tr');
            rows.forEach(row => {
                if (row.textContent.includes(filepath)) {
                    row.remove();
                }
            });
        } else {
            alert(`Error: ${result.error}`);
        }
    } catch (error) {
        console.error('Error deleting file:', error);
        alert('Could not delete file');
    }
}

async function deleteDuplicateGroup(groupId) {
    const files = duplicateData[groupId];
    if (!files || files.length <= 1) return;

    const filesToDelete = files.slice(1);
    let message = `Delete ${filesToDelete.length} duplicate files?\n\n`;
    message += `Keep: ${files[0]}\n\nDelete:\n`;
    message += filesToDelete.slice(0, 5).map(f => `• ${f}`).join('\n');
    if (filesToDelete.length > 5) {
        message += `\n... and ${filesToDelete.length - 5} more`;
    }

    if (!confirm(message)) {
        return;
    }

    try {
        const result = await window.electronAPI.deleteDuplicateGroup(files);
        if (result.success) {
            alert(`Successfully deleted ${result.deletedCount} files`);
            await refreshDuplicates();
        } else {
            alert(`Deleted ${result.deletedCount} files with ${result.errors.length} errors`);
        }
    } catch (error) {
        console.error('Error deleting duplicates:', error);
        alert('Could not delete duplicates');
    }
}

async function openDuplicateLocations(groupId) {
    const files = duplicateData[groupId];
    if (!files) return;

    try {
        // Open first 3 files
        for (let i = 0; i < Math.min(3, files.length); i++) {
            await window.electronAPI.openFileLocation(files[i]);
        }
    } catch (error) {
        console.error('Error opening duplicate locations:', error);
        alert('Could not open file locations');
    }
}

function clearResults() {
    document.getElementById('largeFilesBody').innerHTML =
        '<tr class="empty-state"><td colspan="3">No scan results yet. Click "Start Scan" to begin.</td></tr>';
    document.getElementById('duplicatesBody').innerHTML =
        '<tr class="empty-state"><td colspan="6">No duplicates found yet. Run a scan to find duplicate files.</td></tr>';
    document.getElementById('duplicatesInfo').textContent = 'No duplicates found yet';
    document.getElementById('commandsText').value = '';
    duplicateData = {};
    updateProgress('Ready to scan', false);
}

async function saveCommands() {
    const commands = document.getElementById('commandsText').value;
    if (!commands.trim()) {
        alert('No commands to save');
        return;
    }

    try {
        const result = await window.electronAPI.saveCommands(commands);
        if (result.success) {
            alert(`Commands saved to ${result.filename}`);
        } else {
            alert(`Error: ${result.error}`);
        }
    } catch (error) {
        console.error('Error saving commands:', error);
        alert('Could not save commands');
    }
}

function copyCommands() {
    const commands = document.getElementById('commandsText').value;
    if (!commands.trim()) {
        alert('No commands to copy');
        return;
    }

    navigator.clipboard.writeText(commands).then(() => {
        alert('Commands copied to clipboard');
    }).catch(err => {
        console.error('Error copying to clipboard:', err);
        alert('Could not copy to clipboard');
    });
}

function clearCommands() {
    document.getElementById('commandsText').value = '';
}

// Utility functions
function formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/'/g, "\\'");
}
