// Disk Scanner - Python subprocess wrapper
const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

class DiskScanner {
    constructor() {
        this.pythonProcess = null;
        this.onProgress = null;
        this.commandQueue = [];
        this.currentCommand = null;
    }

    // Get Python executable path
    getPythonCommand() {
        // Try different Python commands
        return process.platform === 'win32' ? 'python' : 'python3';
    }

    // Start Python backend process
    startPythonProcess() {
        if (this.pythonProcess) {
            return; // Already running
        }

        const pythonScript = path.join(__dirname, 'scanner_backend.py');
        const pythonCmd = this.getPythonCommand();

        console.log('[DiskScanner] Starting Python backend:', pythonCmd, pythonScript);

        this.pythonProcess = spawn(pythonCmd, [pythonScript], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        // Set up readline interface for line-by-line reading
        const rl = readline.createInterface({
            input: this.pythonProcess.stdout,
            crlfDelay: Infinity
        });

        rl.on('line', (line) => {
            try {
                const message = JSON.parse(line);
                this.handlePythonMessage(message);
            } catch (error) {
                console.error('[DiskScanner] Failed to parse Python output:', line);
            }
        });

        this.pythonProcess.stderr.on('data', (data) => {
            console.error('[Python stderr]:', data.toString());
        });

        this.pythonProcess.on('close', (code) => {
            console.log('[DiskScanner] Python process exited with code:', code);
            this.pythonProcess = null;
        });

        this.pythonProcess.on('error', (error) => {
            console.error('[DiskScanner] Failed to start Python:', error);
            this.pythonProcess = null;
        });
    }

    // Handle messages from Python
    handlePythonMessage(message) {
        console.log('[DiskScanner] Python message:', message.type);

        if (message.type === 'progress' || message.type === 'status') {
            if (this.onProgress) {
                this.onProgress(message);
            }
        } else if (message.type === 'result') {
            if (this.currentCommand && this.currentCommand.resolve) {
                this.currentCommand.resolve(message.data);
                this.currentCommand = null;
                this.processNextCommand();
            }
        } else if (message.type === 'error') {
            if (this.currentCommand && this.currentCommand.reject) {
                this.currentCommand.reject(new Error(message.message));
                this.currentCommand = null;
                this.processNextCommand();
            }
        }
    }

    // Send command to Python
    sendCommand(command) {
        return new Promise((resolve, reject) => {
            this.commandQueue.push({ command, resolve, reject });
            if (!this.currentCommand) {
                this.processNextCommand();
            }
        });
    }

    // Process next command in queue
    processNextCommand() {
        if (this.commandQueue.length === 0) {
            return;
        }

        this.currentCommand = this.commandQueue.shift();

        if (!this.pythonProcess) {
            this.startPythonProcess();
            // Wait a bit for Python to start
            setTimeout(() => {
                this.pythonProcess.stdin.write(JSON.stringify(this.currentCommand.command) + '\n');
            }, 100);
        } else {
            this.pythonProcess.stdin.write(JSON.stringify(this.currentCommand.command) + '\n');
        }
    }

    // Get available drives (from Python)
    async getAvailableDrives() {
        console.log('[DiskScanner] Getting drives from Python...');
        return this.sendCommand({ command: 'get_drives' });
    }

    // Main scan function (delegated to Python)
    async scan(drivesSelection, minSizeMB, skipFolders = []) {
        console.log('[DiskScanner] Starting scan via Python:', { drivesSelection, minSizeMB, skipFolders });
        return this.sendCommand({
            command: 'start_scan',
            drives: drivesSelection,
            minSizeMB: minSizeMB,
            skipFolders: skipFolders
        });
    }

    // Refresh duplicates (delegated to Python)
    async refreshDuplicates() {
        console.log('[DiskScanner] Refreshing duplicates via Python...');
        return this.sendCommand({ command: 'refresh_duplicates' });
    }

    // Stop scanning
    stop() {
        if (this.pythonProcess) {
            console.log('[DiskScanner] Stopping Python process...');
            this.pythonProcess.kill();
            this.pythonProcess = null;
        }
    }

    // Cleanup
    cleanup() {
        this.stop();
    }
}

module.exports = DiskScanner;
