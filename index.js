const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('./db'); 

const app = express();
const port = 3000;
const saltRounds = 10; 

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); 


function generateApiKey() {
    const randomBytes = crypto.randomBytes(16).toString('hex').toUpperCase();
    return `KEY-${randomBytes.slice(0, 8)}-${randomBytes.slice(8, 16)}-${randomBytes.slice(16, 24)}-${randomBytes.slice(24, 32)}`;
}

function getTodayDate() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/save-user', (req, res) => {
    const { first_name, last_name, email } = req.body; 
    
    if (!first_name || !last_name || !email)
        return res.status(400).json({ success: false, message: "Nama dan Email wajib diisi" });

    const todayDate = getTodayDate();

    const checkEmailSql = "SELECT id FROM users_apikey WHERE email = ?"; 
    db.query(checkEmailSql, [email], (err, resultEmail) => {
        if (err) {
            console.error("Error saat cek email:", err);
            return res.status(500).json({ success: false, message: "Server error saat validasi Email. Cek log server untuk detail DB error." });
        }
        if (resultEmail.length > 0) return res.status(400).json({ success: false, message: "Email sudah terdaftar!" });

        const insertSql = `
            INSERT INTO users_apikey (firstname, lastname, email, start_date, last_date)
            VALUES (?, ?, ?, ?, ?)
        `;
        db.query(insertSql, [first_name, last_name, email, todayDate, todayDate], (err, resultUser) => {
            if (err) {
                console.error("Gagal menyimpan user:", err);
                return res.status(500).json({ success: false, message: "Gagal menyimpan user ke database. Cek log server: pastikan kolom DB Anda ada dan tipe datanya benar." });
            }

            res.json({
                success: true,
                message: "User berhasil disimpan!",
                user_id: resultUser.insertId
            });
        });
    });
});

app.post('/create', (req, res) => {
    const { service_name, user_id } = req.body;
    
    if (!service_name || !user_id) 
        return res.status(400).json({ error: 'Service name dan User ID wajib diisi' });

    const apiKey = generateApiKey();

    const sql = `
        INSERT INTO api_keys (api_key, service_name, user_id, expires_at) 
        VALUES (?, ?, ?, NULL) 
    `; 
    
    db.query(sql, [apiKey, service_name, user_id], (err) => {
        if (err) {
            console.error('❌ Database Error saat INSERT API Key:', err);
            return res.status(500).json({ error: 'Gagal menyimpan API Key ke database. Cek Foreign Key atau log server.' });
        }
        res.json({ apiKey, message: 'API Key berhasil dibuat & disimpan!' });
    });
});


app.post('/cekapi', (req, res) => {
    const { api_key } = req.body
    
    if (!api_key) {
      return res.status(400).json({ error: 'API key wajib dikirim' })
    }
    
    const sql = `
        SELECT a.service_name, a.created_at, u.firstname, u.email 
        FROM api_keys a 
        JOIN users_apikey u ON a.user_id = u.id 
        WHERE a.api_key = ?
    `;

    db.query(sql, [api_key], (err, results) => {
      if (err) {
        console.error('❌ Error cek API key:', err)
        return res.status(500).json({ error: 'Terjadi kesalahan server saat cek API key' })
      }
    
      if (results.length > 0) {
        res.json({ valid: true, service_name: results[0].service_name, created_at: results[0].created_at, user: results[0].firstname })
      } else {
        res.json({ valid: false, message: 'API key tidak ditemukan' })
      }
    })
});


app.post('/admin/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email dan password wajib diisi." });
    }

    try {
        const checkSql = "SELECT id FROM admins WHERE email = ?";
        db.query(checkSql, [email], async (err, result) => {
            if (err) {
                console.error('Database error saat cek admin:', err);
                return res.status(500).json({ success: false, message: "Server error: Gagal cek database admin." });
            }

            if (result.length > 0) {
                return res.status(400).json({ success: false, message: "Email ini sudah terdaftar sebagai Admin." });
            }

            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const insertSql = "INSERT INTO admins (email, password) VALUES (?, ?)"; 
            
            db.query(insertSql, [email, hashedPassword], (err) => {
                if (err) {
                    console.error('Database error saat registrasi admin:', err);
                    return res.status(500).json({ success: false, message: "Server error: Gagal menyimpan admin. Cek skema tabel admins." });
                }
                res.json({ success: true, message: "Admin berhasil didaftarkan!" });
            });
        });

    } catch (error) {
        console.error('Error proses registrasi admin:', error);
        res.status(500).json({ success: false, message: "Terjadi error internal saat registrasi admin." });
    }
});


app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;
    

    const sql = "SELECT password FROM admins WHERE email = ?";
    
    db.query(sql, [email], async (err, results) => {
        if (err) {
            console.error('Database error saat login admin:', err);
            return res.status(500).json({ success: false, message: "Server error saat mencari admin." });
        }
        
        if (results.length === 0) {
            return res.status(401).json({ success: false, message: "Email atau Password salah." });
        }
        
        const hashedPassword = results[0].password;
        

        const match = await bcrypt.compare(password, hashedPassword);
        
        if (match) {
            res.json({ success: true, message: "Login berhasil!" });
        } else {
            res.status(401).json({ success: false, message: "Email atau Password salah." });
        }
    });
});


app.get('/admin/users', (req, res) => {
    const sql = `
        SELECT u.id, u.firstname, u.lastname, u.email, u.created_at, GROUP_CONCAT(a.api_key) as assigned_keys 
        FROM users_apikey u 
        LEFT JOIN api_keys a ON u.id = a.user_id 
        GROUP BY u.id
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Gagal mengambil data user" });
        res.json(results);
    });
});


app.get('/admin/apikeys', (req, res) => {
   
    const sql = `
        SELECT a.id, a.service_name, a.api_key, a.created_at, CONCAT(u.firstname, ' ', u.lastname) AS assigned_to
        FROM api_keys a
        JOIN users_apikey u ON a.user_id = u.id
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Gagal mengambil API keys" });
        res.json(results);
    });
});

app.delete('/admin/users/:id', (req, res) => {
    const userId = req.params.id;
    const sql = "DELETE FROM users_apikey WHERE id = ?"; 
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error('Delete User Error:', err);
            return res.status(500).json({ success: false, message: "Gagal menghapus user." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "User tidak ditemukan." });
        }
        res.json({ success: true, message: "User berhasil dihapus!" });
    });
});


app.delete('/admin/apikeys/:id', (req, res) => {
    const apiKeyId = req.params.id;
    const sql = "DELETE FROM api_keys WHERE id = ?"; 
    db.query(sql, [apiKeyId], (err, result) => {
        if (err) {
            console.error('Delete API Key Error:', err);
            return res.status(500).json({ success: false, message: "Gagal menghapus API Key." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "API Key tidak ditemukan." });
        }
        res.json({ success: true, message: "API Key berhasil dihapus!" });
    });
});

app.listen(port, () => {
    console.log(`🚀 Server berjalan di http://localhost:${port}`);
});