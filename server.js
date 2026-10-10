const express = require('express');
const cors = require('cors');
const multer = require('multer');
const AdmZip = require('adm-zip');
require('dotenv').config();

const { runStaticScan } = require('./scanner/rules');
const { analyzeWithAI } = require('./scanner/aiEngine');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Supported source code extensions across major languages
const SUPPORTED_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx',
  '.py',
  '.c', '.cpp', '.cc', '.h', '.hpp',
  '.java',
  '.go',
  '.rs',
  '.php',
  '.cs',
  '.rb',
  '.sql',
  '.sh', '.bash',
  '.sol'
];

function isSupportedSourceFile(filename) {
  const lower = filename.toLowerCase();
  return SUPPORTED_EXTENSIONS.some(ext => lower.endsWith(ext));
}

// 1. Text Snippet Scanner
app.post('/api/scan', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required.' });

    const staticResults = runStaticScan(code);
    const aiResults = await analyzeWithAI(code, staticResults);

    res.json({
      success: true,
      originalCode: code,
      staticFindings: staticResults,
      aiAnalysis: aiResults
    });
  } catch (error) {
    res.status(500).json({ error: 'Scan error' });
  }
});

// 2. Multi-Language ZIP Project Scanner
app.post('/api/scan-zip', upload.single('projectZip'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'ZIP file required.' });

    const zip = new AdmZip(req.file.buffer);
    const zipEntries = zip.getEntries();
    let aggregatedCode = '';
    let totalFilesChecked = 0;

    zipEntries.forEach(entry => {
      if (entry.isDirectory) return;

      const path = entry.entryName;
      // Skip dependency folders and build artifacts
      if (
        path.includes('node_modules') ||
        path.includes('.git') ||
        path.includes('venv') ||
        path.includes('__pycache__') ||
        path.includes('dist') ||
        path.includes('build')
      ) {
        return;
      }

      if (isSupportedSourceFile(path)) {
        totalFilesChecked++;
        aggregatedCode += `\n// File: ${path}\n` + entry.getData().toString('utf8');
      }
    });

    if (!aggregatedCode) {
      return res.status(400).json({
        error: 'No supported source files found in ZIP (supports JS, TS, Python, C, C++, Java, Go, Rust, PHP, C#, etc.).'
      });
    }

    const staticResults = runStaticScan(aggregatedCode);
    const aiResults = await analyzeWithAI(aggregatedCode.slice(0, 15000), staticResults);

    res.json({
      success: true,
      originalCode: aggregatedCode.slice(0, 5000),
      filesScanned: totalFilesChecked,
      staticFindings: staticResults,
      aiAnalysis: aiResults
    });
  } catch (error) {
    res.status(500).json({ error: 'Error processing ZIP file' });
  }
});

// 3. Multi-Language GitHub Repository Scanner
app.post('/api/scan-github', async (req, res) => {
  try {
    const { repoUrl } = req.body;
    if (!repoUrl) return res.status(400).json({ error: 'GitHub Repo URL is required.' });

    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    if (!match) return res.status(400).json({ error: 'Invalid GitHub URL format.' });

    const owner = match[1];
    const repo = match[2].replace('.git', '');

    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents`;
    const response = await fetch(apiUrl, {
      headers: { 'User-Agent': 'AutoAudit-AI' }
    });

    if (!response.ok) {
      return res.status(400).json({ error: 'Could not access repository. Ensure it is public.' });
    }

    const contents = await response.json();
    let aggregatedCode = '';
    let filesCount = 0;

    for (const item of contents) {
      if (item.type === 'file' && isSupportedSourceFile(item.name)) {
        const fileRes = await fetch(item.download_url);
        const text = await fileRes.text();
        aggregatedCode += `\n// File: ${item.name}\n` + text;
        filesCount++;
      }
    }

    if (!aggregatedCode) {
      return res.status(400).json({
        error: 'No supported source files found in repository root.'
      });
    }

    const staticResults = runStaticScan(aggregatedCode);
    const aiResults = await analyzeWithAI(aggregatedCode.slice(0, 15000), staticResults);

    res.json({
      success: true,
      originalCode: aggregatedCode.slice(0, 5000),
      filesScanned: filesCount,
      staticFindings: staticResults,
      aiAnalysis: aiResults
    });
  } catch (error) {
    res.status(500).json({ error: 'GitHub scan failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AutoAudit AI running at: http://localhost:${PORT}`);
});