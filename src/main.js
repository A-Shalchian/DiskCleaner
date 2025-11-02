// Disk Cleaner - Electron Main Process
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const DiskScanner = require('./diskScanner');

let mainWindow;
let scanner;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: true
        },
        icon: path.join(__dirname, '../build/icon.png'),
        backgroundColor: '#f8f9fa',
        show: false,
        frame: true,
        titleBarStyle: 'default'
    });

    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));

    // Show window when ready
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Open DevTools in development
    if (process.argv.includes('--dev')) {
        mainWindow.webContents.openDevTools();
    }

    mainWindow.on('closed', () => {
        mainWindow = null;
        if (scanner) {
            scanner.stop();
        }
    });
}

// App lifecycle
app.whenReady().then(() => {
    scanner = new DiskScanner();
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// IPC Handlers

// Get app version
ipcMain.handle('get-version', () => {
    return app.getVersion();
});

// Get available drives
ipcMain.handle('get-drives', async () => {
    try {
        const drives = await scanner.getAvailableDrives();
        console.log('[main] Returning drives:', drives);
        return drives;
    } catch (error) {
        console.error('[main] Error getting drives:', error);
        return [];
    }
});

// Start scan
ipcMain.handle('start-scan', async (event, { drives, minSizeMB }) => {
    try {
        console.log('[main] Starting scan:', { drives, minSizeMB });

        // Set up progress callback
        scanner.onProgress = (data) => {
            mainWindow.webContents.send('scan-progress', data);
        };

        const results = await scanner.scan(drives, minSizeMB);
        return results;
    } catch (error) {
        console.error('[main] Scan error:', error);
        throw error;
    }
});

// Stop scan
ipcMain.handle('stop-scan', async () => {
    try {
        scanner.stop();
        return { success: true };
    } catch (error) {
        console.error('[main] Stop scan error:', error);
        return { success: false, error: error.message };
    }
});

// Open file location
ipcMain.handle('open-file-location', async (event, filepath) => {
    try {
        shell.showItemInFolder(filepath);
        return { success: true };
    } catch (error) {
        console.error('[main] Error opening file location:', error);
        return { success: false, error: error.message };
    }
});

// Delete file
ipcMain.handle('delete-file', async (event, filepath) => {
    const fs = require('fs').promises;
    try {
        await fs.unlink(filepath);
        return { success: true };
    } catch (error) {
        console.error('[main] Error deleting file:', error);
        return { success: false, error: error.message };
    }
});

// Delete duplicate group
ipcMain.handle('delete-duplicate-group', async (event, filepaths) => {
    const fs = require('fs').promises;
    const filesToDelete = filepaths.slice(1); // Keep first file
    let deletedCount = 0;
    const errors = [];

    for (const filepath of filesToDelete) {
        try {
            await fs.unlink(filepath);
            deletedCount++;
        } catch (error) {
            errors.push(`${filepath}: ${error.message}`);
        }
    }

    return {
        success: deletedCount > 0,
        deletedCount,
        errors
    };
});

// Save commands to file
ipcMain.handle('save-commands', async (event, commands) => {
    try {
        const { filePath } = await dialog.showSaveDialog(mainWindow, {
            title: 'Save Delete Commands',
            defaultPath: 'delete_commands.bat',
            filters: [
                { name: 'Batch Files', extensions: ['bat'] },
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        });

        if (filePath) {
            const fs = require('fs').promises;
            await fs.writeFile(filePath, commands, 'utf-8');
            return { success: true, filename: filePath };
        } else {
            return { success: false, error: 'No file selected' };
        }
    } catch (error) {
        console.error('[main] Error saving commands:', error);
        return { success: false, error: error.message };
    }
});

// Refresh duplicates
ipcMain.handle('refresh-duplicates', async () => {
    try {
        scanner.onProgress = (data) => {
            mainWindow.webContents.send('scan-progress', data);
        };

        const results = await scanner.refreshDuplicates();
        return results;
    } catch (error) {
        console.error('[main] Refresh duplicates error:', error);
        throw error;
    }
});
