// server.js

const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');

app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'files', filename);

    // Set the proper headers for file download
    res.setHeader('Content-Disposition', 'attachment; filename=' + filename);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Transfer-Encoding', 'binary');

    const stat = fs.statSync(filePath);
    res.setHeader('Content-Length', stat.size);

    const readStream = fs.createReadStream(filePath);
    readStream.on('open', () => {
        readStream.pipe(res);
    });
    readStream.on('error', (err) => {
        res.status(500).json({ error: 'File not found or unable to download' });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
