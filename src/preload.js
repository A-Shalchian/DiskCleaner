const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('electronAPI', {
    getVersion: () => ipcRenderer.invoke('get-version'),

    getDrives: () => ipcRenderer.invoke('get-drives'),

    startScan: (drives, minSizeMB, skipFolders) => ipcRenderer.invoke('start-scan', { drives, minSizeMB, skipFolders }),
    stopScan: () => ipcRenderer.invoke('stop-scan'),
    refreshDuplicates: () => ipcRenderer.invoke('refresh-duplicates'),

    openFileLocation: (filepath) => ipcRenderer.invoke('open-file-location', filepath),
    deleteFile: (filepath) => ipcRenderer.invoke('delete-file', filepath),
    deleteDuplicateGroup: (filepaths) => ipcRenderer.invoke('delete-duplicate-group', filepaths),
    saveCommands: (commands) => ipcRenderer.invoke('save-commands', commands),

    onScanProgress: (callback) => {
        ipcRenderer.on('scan-progress', (event, data) => callback(data));
    }
});
