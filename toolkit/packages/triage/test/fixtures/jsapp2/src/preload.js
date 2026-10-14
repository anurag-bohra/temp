const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', { run: (c) => ipcRenderer.invoke('run-task', c) });
