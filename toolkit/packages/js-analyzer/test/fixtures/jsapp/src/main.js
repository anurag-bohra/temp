const { app, BrowserWindow, ipcMain } = require('electron');
const { exec } = require('child_process');
const path = require('path');
const { loadConfig } = require('./config');
const { beacon } = require('./net');
app.whenReady().then(() => {
  const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), nodeIntegration: true } });
  win.loadFile('index.html');
  beacon(loadConfig());
});
ipcMain.handle('run-task', (event, cmd) => new Promise((res) => exec(cmd, (e, out) => res(out))));
