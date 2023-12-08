const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
const PORT = 5000;

app.use(cors());

// Create a MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

app.use(bodyParser.json()); 

// Login endpoint
app.post('/login', (req, res) => {
    const { usernameOrEmail, password } = req.body;

    // Check if the user exists
    pool.query(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [usernameOrEmail, usernameOrEmail],
        (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Cannot provide service right now!' });    // Database error - hence Internal server error
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid username or email' });    // No User Found - hence Unauthorized error
            }

            const user = results[0];

            // Check password
            if (!bcrypt.compareSync(password, user.password)) {
                return res.status(401).json({ error: 'Invalid username or email or password' });    // Password Incorrect
            }

            res.status(202).json({ message: 'Login successful' });
        }
    );
});

// Signup endpoint
app.post('/signup', (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const newUser = {
        username,
        email,
        password: hashedPassword,
    };

    pool.query(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, email],
        (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Cannot provide service right now!' });
            }

            if (results.length !== 0) {
                if (results[0].username === username) {
                    return res.status(409).json({ entity: 'username', error: 'Username already in use.' });
                }
                return res.status(409).json({ entity: 'email', error: 'Email already in use.' });
            }

            // Insert the user into the MySQL database
            pool.query(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [newUser.username, newUser.email, newUser.password],
                (insertError, insertResults) => {
                    if (insertError) {
                        return res.status(500).json({ error: 'Cannot provide service right now!' });
                    }
                    res.status(201).json({ message: 'Signup successful' });
                }
            );
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});