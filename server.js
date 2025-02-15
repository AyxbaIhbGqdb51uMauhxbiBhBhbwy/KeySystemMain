const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
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

// Helper function to generate a token with a 5-minute expiration
function generateToken() {
    try {
        // Ensure SECRET_KEY is set
        if (!process.env.SECRET_KEY) {
            throw new Error('couldnt find key');
        }
        
        // Generate the token
        return jwt.sign({}, process.env.SECRET_KEY, { expiresIn: '30s' });
    } catch (error) {
        // Log error and throw it to be handled by the route
        console.error('Error generating token:', error.message);
        throw error;
    }
}

// Check Key route with error handling
app.post('/check-key', (req, res) => {
    try {
        const { key } = req.body;

        // Ensure key is provided
        if (!key) {
            return res.status(400).json({ error: 'Key is required' });
        }

        const validKey = process.env.STATIC_KEY;

        // Ensure STATIC_KEY is set
        if (!validKey) {
            throw new Error('couldnt find key');
        }

        // Check if the provided key matches the valid key
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

    // Ensure token is provided
    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    try {
        // Ensure SECRET_KEY is set
        if (!process.env.SECRET_KEY) {
            throw new Error('couldnt find key');
        }

        // Verify the token
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
app.get('/get-key', (req, res) => {
    const referrer = req.get('referer') || '';
    const ipAddress = req.ip; // Use IP address as a unique identifier

    // List of valid referrers (adjust this list based on observed variations)
    const validReferrers = [
        'linkvertise.com',
        'work.ink',
        // Add other known variations
    ];

    // Check if the referrer matches any known valid referrer patterns
    const isValidReferrer = validReferrers.some(validReferrer =>
        referrer.includes(validReferrer)
    );

    if (!isValidReferrer) {
        // Path to the HTML file
        const filePath = path.join(__dirname, 'accessdenied.html');
        
        // Read and send the HTML file
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                // Handle file read error
                res.status(500).send('An error occurred while processing your request.');
                return;
            }
    
            // Send the HTML file with a 403 status code
            res.status(403).send(data);
        });
    } else {
        // Return the static key
        const staticKey = process.env.STATIC_KEY;
        const timestamp = process.env.TIMESTAMP;

        // Check if the static key is defined
        if (!staticKey) {
            return res.status(500).json({ error: 'Internal Server Error: Key not found!' });
        }

        res.setHeader('Content-Type', 'text/html');
        res.send(generateHtmlResponse(staticKey, timestamp));
    }
});

// Helper function to generate HTML response with the key
function generateHtmlResponse(key, timestamp) {
    const keysitePath = path.join(__dirname, 'keysite.html');
    
    // Read the HTML keysite from file synchronously
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
