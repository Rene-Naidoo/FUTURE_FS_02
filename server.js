// ----------------- IMPORTS -----------------
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();

// ----------------- MIDDLEWARE -----------------
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(bodyParser.json());
app.use(express.static('public'));

app.use(session({
    secret: 'mycrmsecret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false
    }
}));

// ----------------- DATABASE -----------------
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'TealRene2702',
    database: 'mini_crm'
});

db.connect(err => {
    if (err) console.error('DB connection failed:', err);
    else console.log('Connected to MySQL');
});

// ----------------- AUTH MIDDLEWARE -----------------
function isLoggedIn(req, res, next) {
    if (req.session.admin) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Not logged in' });
    }
}

// ----------------- LOGIN -----------------
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM admins WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (results.length === 0)
            return res.json({ success: false, message: 'User not found' });

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ success: false, message: 'Error checking password' });
            if (!isMatch)
                return res.json({ success: false, message: 'Incorrect password' });

            req.session.admin = { id: user.id, username: user.username };

            res.json({ success: true, adminId: user.id });
        });
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// ----------------- LEADS APIs -----------------

// GET leads with filtering + sorting
app.get('/leads', isLoggedIn, (req, res) => {
    let query = 'SELECT * FROM leads';
    let conditions = [];
    let params = [];

    // Filtering
    if (req.query.status) {
        conditions.push('status = ?');
        params.push(req.query.status);
    }

    if (req.query.source) {
        conditions.push('source = ?');
        params.push(req.query.source);
    }

    if (conditions.length > 0) {
        query += ' WHERE ' + conditions.join(' AND ');
    }

    // Sorting
    if (req.query.sortBy === 'date') {
        query += ' ORDER BY created_at DESC';
    } else if (req.query.sortBy === 'status') {
        query += ' ORDER BY status ASC';
    } else if (req.query.sortBy === 'source') {
        query += ' ORDER BY source ASC';
    } else {
        query += ' ORDER BY created_at DESC';
    }

    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json(results);
    });
});

// ADD lead
app.post('/leads', isLoggedIn, (req, res) => {
    const { name, email, source } = req.body;

    if (!name || !email)
        return res.status(400).json({ success: false, message: 'Name and email required' });

    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email))
        return res.status(400).json({ success: false, message: 'Invalid email' });

    const query = `
        INSERT INTO leads (name, email, source, status, created_at)
        VALUES (?, ?, ?, 'New', NOW())
    `;

    db.query(query, [name, email, source], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: err.message });

        res.json({ success: true, message: 'Lead added!', id: result.insertId });
    });
});

// UPDATE lead
app.put('/leads/:id', isLoggedIn, (req, res) => {
    const { status, notes } = req.body;

    db.query(
        'UPDATE leads SET status = ?, notes = ? WHERE id = ?',
        [status, notes, req.params.id],
        (err, result) => {
            if (err)
                return res.status(500).json({ success: false, message: err.message });

            if (result.affectedRows === 0)
                return res.status(404).json({ success: false, message: 'Lead not found' });

            res.json({ success: true, message: 'Lead updated!' });
        }
    );
});

// DELETE lead
app.delete('/leads/:id', isLoggedIn, (req, res) => {
    db.query('DELETE FROM leads WHERE id = ?', [req.params.id], (err, result) => {
        if (err)
            return res.status(500).json({ success: false, message: err.message });

        if (result.affectedRows === 0)
            return res.status(404).json({ success: false, message: 'Lead not found' });

        res.json({ success: true, message: 'Lead deleted!' });
    });
});

// ----------------- ADMIN PASSWORD UPDATE -----------------
app.put('/admins/:id/password', isLoggedIn, (req, res) => {
    const adminId = req.params.id;
    const { oldPassword, newPassword } = req.body;

    db.query('SELECT * FROM admins WHERE id = ?', [adminId], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        if (results.length === 0)
            return res.status(404).json({ success: false, message: 'Admin not found' });

        const admin = results[0];

        bcrypt.compare(oldPassword, admin.password, (err, isMatch) => {
            if (err)
                return res.status(500).json({ success: false, message: 'Error checking password' });

            if (!isMatch)
                return res.status(400).json({ success: false, message: 'Old password incorrect' });

            const hashed = bcrypt.hashSync(newPassword, 10);

            db.query('UPDATE admins SET password = ? WHERE id = ?', [hashed, adminId], err => {
                if (err)
                    return res.status(500).json({ success: false, message: err.message });

                res.json({ success: true, message: 'Password updated successfully' });
            });
        });
    });
});

// ----------------- START SERVER -----------------
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
