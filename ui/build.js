// Baut ui/index.html aus src.html und fügt forge + core.js ein (die Datei wird per go:embed in die Exe gelegt).
const fs = require('node:fs');
const path = require('node:path');
const read = (p) => fs.readFileSync(path.join(__dirname, p), 'utf8');
const safe = (js) => js.replace(/<\/(script)/gi, '<\\/$1');
let html = read('src.html');
html = html.replace('/*@@FORGE@@*/', () => safe(read('vendor/forge.min.js').replace(/\/\/# sourceMappingURL=.*$/m, '')));
html = html.replace('/*@@CORE@@*/', () => safe(read('vendor/core.js')));
if (/\/\*@@[A-Z]+@@\*\//.test(html)) throw new Error('Platzhalter nicht ersetzt');
fs.writeFileSync(path.join(__dirname, 'index.html'), html);
console.log('index.html:', (Buffer.byteLength(html) / 1024).toFixed(0), 'KB');
