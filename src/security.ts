import express from 'express';

const app = express();
const port = 3000;

app.get('/greet', (req, res) => {
    const name = req.query.name as string;
    //   VULNERABILITY 1 : **CRITICAL: Reflected XSS (Cross-Site Scripting) 
    res.send(`<h1>Hello, ${name}</h1>`);
});

app.get('/exec', (req, res) => {
    const cmd = req.query.cmd as string;
    const { exec } = require('child_process');
    //   VULNERABILITY 2 **CRITICAL: Command Injection

    exec(cmd, (error: any, stdout: string, stderr: string) => {
        if (error) {
            //  VULNERABILITY 3: **MEDIUM: Information Disclosure 
            res.send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
});

app.get('/file', (req, res) => {
    const path = req.query.path as string;
    const fs = require('fs');
    //  VULNERABILITY 4: **CRITICAL: Path Traversal / Directory Traversal
    fs.readFile(path, 'utf8', (err: any, data: string) => {
        if (err) {
            //   VULNERABILITY 5: **LOW: Insecure Error Handling
            res.send('File not found');
            return;
        }
        res.send(data);
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    //   VULNERABILITY 6 : **MEDIUM: Information Disclosure in Logs 
});