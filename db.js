// Database connection pool
const mysql = require("mysql2/promise")

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'smu.cluster-c382gsmgefll.us-east-2.rds.amazonaws.com',
  port: 3306,
  user: process.env.DB_USER || 'Adam',
  password: process.env.DB_PASS || 'AdamSMU',
  database: process.env.DB_NAME || 'SMUSchema'
})

module.exports = pool