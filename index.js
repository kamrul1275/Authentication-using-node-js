const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authenticateToken = require('./authMiddleware'); // Import the middleware

const app = express();
const port = 3000;

app.use(bodyParser.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'auth_db'
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to database');
});

// Registration route
// app.post('/register', async (req, res) => {
//     const { username,email, password } = req.body;

//     if (!username ||!email || !password) {
//         return res.status(400).send('Username, email password, and  are required');
//     }

//     try {
//         const hashedPassword = await bcrypt.hash(password, 10);

//         db.query('INSERT INTO users (username,email, password) VALUES (?, ?, ?)', [username,email, hashedPassword], (err, result) => {
//             if (err) throw err;
//             res.status(201).send('User registation successful');
//         });
//     } catch (error) {
//         res.status(500).send('Error hashing password');
//     }
// });






app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).send('Username, email, and password are required');
    }

    try {
        // Check if the email already exists
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) throw err;

            if (results.length > 0) {
                return res.status(409).send('Email already registered');
            } else {
                // Hash the password
                const hashedPassword = await bcrypt.hash(password, 10);

                // Insert the new user
                db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err, result) => {
                    if (err) throw err;
                    res.status(201).send('User registration successful');
                });
            }
        });
    } catch (error) {
        res.status(500).send('Error hashing password');
    }
});







// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;

        if (results.length === 0) {
            return res.status(401).send('Invalid credentials');
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).send('Invalid credentials');
        }

        const token = jwt.sign({ id: user.id }, 'your_jwt_secret', { expiresIn: '1h' });
        res.json({ token });
    });


});

// Protected route
app.get('/dashboard', authenticateToken ,(req, res) => {

   
    try {
        res.send('Welcome to Dashboard.....');
    } catch (error) {
        res.status(500).send('Error');
        
    }
});

// Protected route
app.get('/profile', authenticateToken, (req, res) => {

    res.send('Profile');
});

// Protected route


// logout
app.post('/logout', (req, res) => {
    res.send('Logout successful');
});

// update


// Update profile route
app.put('/profile/update', authenticateToken, (req, res) => {
    const { username, email } = req.body;
    const userId = req.user.id;

    if (!username || !email) {
        return res.status(400).send('Username and email are required');
    }

    db.query('UPDATE users SET username = ?, email = ? WHERE id = ?', [username, email, userId], (err, result) => {
        if (err) throw err;
        res.send('Profile updated');
    });
});

// Delete profile route
app.delete('/profile/delete', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
        if (err) throw err;
        res.send('Profile deleted');
    });
});

// Get profile route
app.get('/profile', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) throw err;
        res.json(results[0]);
    });
});




app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});