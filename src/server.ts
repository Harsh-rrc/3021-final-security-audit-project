import express from 'express';

const app = express();
const port = 3000;

app.get('/greet', (req, res) => {
    const name = req.query.name as string;
    res.send(`<h1>Hello, ${name}</h1>`); // Potential XSS vulnerability if name contains script
});

app.get('/exec', (req, res) => {
    const cmd = req.query.cmd as string;
    const { exec } = require('child_process');
    exec(cmd, (error: any, stdout: string, stderr: string) => {
        if (error) {
            res.send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    }); // Command injection vulnerability
});

app.get('/file', (req, res) => {
    const path = req.query.path as string;
    const fs = require('fs');
    fs.readFile(path, 'utf8', (err: any, data: string) => {
        if (err) {
            res.send('File not found');
            return;
        }
        res.send(data);
    }); // Path traversal vulnerability
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
