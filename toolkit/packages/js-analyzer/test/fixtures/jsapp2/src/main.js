const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { loadConfig } = require('./config');
const { beacon } = require('./net');
const ALLOWED = new Set(['whoami', 'hostname']);
app.whenReady().then(() => {
  const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), nodeIntegration: false, contextIsolation: true, sandbox: true } });
  win.loadFile('index.html');
  beacon(loadConfig());
});
ipcMain.handle('run-task', (event, cmd) => {
  if (!event.senderFrame || !event.senderFrame.url.startsWith('file://')) throw new Error('untrusted sender');
  if (!ALLOWED.has(cmd)) throw new Error('command not allowed');
  return require('child_process').execFileSync(cmd).toString();
});
