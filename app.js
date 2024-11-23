const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

// ใช้ body-parser สำหรับ JSON (เฉพาะ Version 1 และ 3)
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// คีย์และ IV สำหรับการเข้ารหัส/ถอดรหัส (Version 1 และ 2)
const key = Buffer.from('IVERYLOVECATANDD', 'utf-8'); // 16-byte Key
const iv = Buffer.from('1234567890abcdef', 'utf-8'); // 16-byte IV

// คีย์ลับสำหรับ HMAC (Version 3)
const secretKey = 'super_secret_key';

// Mock ข้อมูลผู้ใช้งาน
const users = {
    "0001": { id: "0001", username: "admin", profile: "This is admin profile." },
    "0002": { id: "0002", username: "user2", profile: "This is user2 profile." },
    "0005": { id: "0005", username: "user5", profile: "This is user5 profile." }
};

// ฟังก์ชันเข้ารหัส AES (CBC)
function encryptAES(data) {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf-8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

// ฟังก์ชันถอดรหัส AES (CBC)
function decryptAES(encrypted) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return JSON.parse(decrypted); // คืนค่าข้อมูล JSON
}

// ฟังก์ชันสร้าง HMAC (Version 3)
function generateHMAC(body, key) {
    return crypto.createHmac('sha256', key).update(JSON.stringify(body)).digest('hex');
}

// Serve App1 (Version 1) Login Page
app.get('/v1_login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'v1_login.html'));
});

// Serve App2 (Version 2) Login Page
app.get('/v2_login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'v2_login.html'));
});

// Serve App3 (Version 3) Login Page
app.get('/v3_login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'v3_login.html'));
});

// API Login (Version 1)
app.post('/v1_login', (req, res) => {
    try {
        const { payload } = req.body; // รับ payload ที่ถูกเข้ารหัส
        const decryptedData = decryptAES(payload); // ถอดรหัส payload
        const { username, password } = decryptedData;

        if (username === 'admin' && password === 'admin') {
            const response = { message: 'Login successful', userId: '0001' };
            const encryptedResponse = encryptAES(response); // เข้ารหัส Response
            res.json({ payload: encryptedResponse });
        } else {
            const response = { message: 'Invalid credentials' };
            const encryptedResponse = encryptAES(response);
            res.status(401).json({ payload: encryptedResponse });
        }
    } catch (err) {
        const response = { message: 'Invalid payload' };
        const encryptedResponse = encryptAES(response);
        res.status(400).json({ payload: encryptedResponse });
    }
});
app.post('/v1_profile', (req, res) => {
    try {
        const { payload } = req.body; // รับ payload ที่ถูกเข้ารหัส
        const decryptedData = decryptAES(payload); // ถอดรหัส payload
        const { id } = decryptedData;

        if (users[id]) {
            const encryptedResponse = encryptAES(users[id]); // เข้ารหัส Response
            res.json({ payload: encryptedResponse });
        } else {
            const response = { message: 'Profile not found' };
            const encryptedResponse = encryptAES(response);
            res.status(404).json({ payload: encryptedResponse });
        }
    } catch (err) {
        const response = { message: 'Invalid payload' };
        const encryptedResponse = encryptAES(response);
        res.status(400).json({ payload: encryptedResponse });
    }
});

// API Login (Version 2)
app.post('/v2_login', express.raw({ type: '*/*' }), (req, res) => {
    try {
        const encryptedBody = req.body.toString(); // รับค่า Raw String
        const decryptedData = decryptAES(encryptedBody); // ถอดรหัส
        const { username, password } = decryptedData;

        if (username === 'admin' && password === 'admin') {
            const response = { message: 'Login successful', userId: '0001' };
            const encryptedResponse = encryptAES(response); // เข้ารหัส Response
            res.send(encryptedResponse); // ส่ง Response เป็นข้อความเข้ารหัสล้วนๆ
        } else {
            const response = { message: 'Invalid credentials' };
            const encryptedResponse = encryptAES(response);
            res.status(401).send(encryptedResponse);
        }
    } catch (err) {
        const response = { message: 'Invalid payload' };
        const encryptedResponse = encryptAES(response);
        res.status(400).send(encryptedResponse);
    }
});

// API Profile (Version 2)
app.post('/v2_profile', express.raw({ type: '*/*' }), (req, res) => {
    try {
        const encryptedBody = req.body.toString(); // รับค่า Raw String
        const decryptedData = decryptAES(encryptedBody); // ถอดรหัส
        const { id } = decryptedData;

        if (users[id]) {
            const encryptedResponse = encryptAES(users[id]); // เข้ารหัส Response
            res.send(encryptedResponse); // ส่ง Response เป็นข้อความเข้ารหัสล้วนๆ
        } else {
            const response = { message: 'Profile not found' };
            const encryptedResponse = encryptAES(response);
            res.status(404).send(encryptedResponse);
        }
    } catch (err) {
        const response = { message: 'Invalid payload' };
        const encryptedResponse = encryptAES(response);
        res.status(400).send(encryptedResponse);
    }
});

// API Login (Version 3)
app.post('/v3_login', (req, res) => {
    try {
        const clientHash = req.headers['hashid']; // รับ hashid จาก Header
        const serverHash = generateHMAC(req.body, secretKey); // สร้าง HMAC ใหม่จาก Body

        if (clientHash !== serverHash) {
            return res.status(403).json({ message: 'Invalid hash, body may have been modified' });
        }

        const { username, password } = req.body;

        if (username === 'admin' && password === 'admin') {
            const response = { message: 'Login successful', userId: '0001' };
            res.json(response);
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(400).json({ message: 'Bad Request', error: err.message });
    }
});

// API Profile (Version 3)
app.post('/v3_profile', (req, res) => {
    try {
        const clientHash = req.headers['hashid']; // รับ hashid จาก Header
        const serverHash = generateHMAC(req.body, secretKey); // สร้าง HMAC ใหม่จาก Body

        if (clientHash !== serverHash) {
            return res.status(403).json({ message: 'Invalid hash, body may have been modified' });
        }

        const { id } = req.body; // ดึง id จาก Body

        if (users[id]) {
            res.json(users[id]); // ส่งข้อมูล Profile
        } else {
            res.status(404).json({ message: 'Profile not found' });
        }
    } catch (err) {
        res.status(400).json({ message: 'Bad Request', error: err.message });
    }
});

// เริ่มเซิร์ฟเวอร์
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
