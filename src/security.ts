import express from 'express';

const app = express();
const port = 3000;

app.get('/greet', (req, res) => {
    const name = req.query.name as string;
    //  **CRITICAL: Reflected XSS (Cross-Site Scripting) - A03:2021-Injection**
    // User input is directly embedded in HTML without sanitization
    // Attack: http://localhost:3000/greet?name=<script>alert('XSS')</script>
    // Fix: Use template escaping or sanitize input
    res.send(`<h1>Hello, ${name}</h1>`);
});

app.get('/exec', (req, res) => {
    const cmd = req.query.cmd as string;
    const { exec } = require('child_process');
    //  **CRITICAL: Command Injection - A03:2021-Injection**
    // User input is passed directly to exec() without validation
    // Attack: http://localhost:3000/exec?cmd=rm%20-rf%20/
    // Attack: http://localhost:3000/exec?cmd=ls;cat%20/etc/passwd
    // Fix: Use whitelist of allowed commands or parameterized execution
    exec(cmd, (error: any, stdout: string, stderr: string) => {
        if (error) {
            // **MEDIUM: Information Disclosure - A01:2021-Broken Access Control**
            // Error messages may reveal system details to attackers
            res.send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
});

app.get('/file', (req, res) => {
    const path = req.query.path as string;
    const fs = require('fs');
    // **CRITICAL: Path Traversal / Directory Traversal - A01:2021-Broken Access Control**
    // User can access arbitrary files outside intended directory
    // Attack: http://localhost:3000/file?path=../../etc/passwd
    // Attack: http://localhost:3000/file?path=C:\Windows\System32\config\SAM
    // Fix: Validate and sanitize file paths, use path normalization
    fs.readFile(path, 'utf8', (err: any, data: string) => {
        if (err) {
            //  **LOW: Insecure Error Handling - A09:2021-Security Logging and Monitoring Failures**
            // Generic error message but could be improved for security
            res.send('File not found');
            return;
        }
        res.send(data);
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    //  **MEDIUM: Information Disclosure in Logs - A09:2021-Security Logging and Monitoring Failures**
    // Console logs may contain sensitive information in production
});