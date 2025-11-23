const mysql = require('mysql2');

const db = mysql.createConnection({
  host: 'localhost',       
  user: 'root',            
  password: 'Coldplayers06',            
  database: 'apikeypws',   
  port : '3308'
});


db.connect((err) => {
  if (err) {
    console.error('❌ Gagal konek ke database:', err);
  } else {
    console.log('✅ Terhubung ke MySQL Database (apikey)');
  }
});

module.exports = db;