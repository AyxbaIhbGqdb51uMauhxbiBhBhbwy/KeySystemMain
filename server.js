const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Import axios for HTTP requests
require('dotenv').config();

const app = express();

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 165, // limit each IP to requests per 5 minutes
    handler: (req, res) => {
        res.status(429).json({
            message: 'You have reached the 5-minute request limit! Please wait a few minutes before trying again.'
        });
    },
    headers: true,
});

// Apply the rate limiter to all requests
app.use(limiter);

// Middleware to parse JSON bodies
app.use(express.json());

// Helper function to generate a key by requesting an external API
async function generateKey() {
    try {
        const response = await axios.get('https://starxkey-backend.vercel.app/generate?expired=1d');
        
        // Extract the 'key' from the response JSON
        const key = response.data.key;
        
        // Ensure the key is available
        if (!key) {
            throw new Error('No key found in the response');
        }

        return key;
    } catch (error) {
        console.error('Error fetching key:', error.message);
        throw error;
    }
}

// Helper function to generate a token with a 5-minute expiration
function generateToken() {
    try {
        if (!process.env.SECRET_KEY) {
            throw new Error('couldnt find key');
        }
        
        return jwt.sign({}, process.env.SECRET_KEY, { expiresIn: '30s' });
    } catch (error) {
        console.error('Error generating token:', error.message);
        throw error;
    }
}

// Check Key route with error handling
app.post('/check-key', async (req, res) => {
    try {
        const { key } = req.body;

        // Ensure key is provided
        if (!key) {
            return res.status(400).json({ error: 'Key is required' });
        }

        const validKey = await generateKey(); // Dynamically generate the key

        // Check if the provided key matches the generated key
        if (key === validKey) {
            const token = generateToken();
            res.json({
                valid: true,
                token: token
            });
        } else {
            res.json({
                valid: false
            });
        }
    } catch (error) {
        console.error('Error in /check-key route:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/validate-token', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    try {
        if (!process.env.SECRET_KEY) {
            throw new Error('couldnt find key');
        }

        jwt.verify(token, process.env.SECRET_KEY, (err) => {
            if (err) {
                return res.json({ valid: false });
            }
            res.json({ valid: true });
        });
    } catch (error) {
        console.error('Error in /validate-token route:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Get Key route (existing)
app.get('/get-key', async (req, res) => {
    const referrer = req.get('referer') || '';
    const ipAddress = req.ip;

    const validReferrers = [
        'linkvertise.com',
        'work.ink',
    ];

    const isValidReferrer = validReferrers.some(validReferrer =>
        referrer.includes(validReferrer)
    );

    if (!isValidReferrer) {
        const filePath = path.join(__dirname, 'accessdenied.html');
        
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.status(500).send('An error occurred while processing your request.');
                return;
            }

            res.status(403).send(data);
        });
    } else {
        try {
            const dynamicKey = await generateKey(); // Dynamically generate key from the API
            const timestamp = new Date().toISOString();

            res.setHeader('Content-Type', 'text/html');
            res.send(generateHtmlResponse(dynamicKey, timestamp));
        } catch (error) {
            res.status(500).json({ error: 'Error generating key' });
        }
    }
});

// Helper function to generate HTML response with the key
function generateHtmlResponse(key, timestamp) {
    const keysitePath = path.join(__dirname, 'keysite.html');
    
    let html = fs.readFileSync(keysitePath, 'utf8');
    html = html.replace('${key}', key);
    html = html.replace('${timestamp}', timestamp);

    return html;
}

app.use((req, res, next) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.use((err, req, res, next) => {
    console.error('Global Error Handler:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
