// server.js - main server file to set up Express server and routes
const express = require("express")
const bodyParser = require("body-parser")
const session = require("express-session")
const path = require("path")
const multer = require("multer")
const pool = require("./db")
const webhookRouter = require("./webhook")

const app = express()
const PORT = process.env.PORT || 3000

// Multer config for CSV uploads (stored in memory)
const csvUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "text/csv" || file.originalname.endsWith(".csv")) {
      cb(null, true)
    } else {
      cb(new Error("Only CSV files are allowed"), false)
    }
  }
})

// Simple CSV parser (no external dependency)
function parseCSV(buffer) {
  const text = buffer.toString("utf-8").replace(/\r\n/g, "\n").replace(/\r/g, "\n")
  const lines = text.split("\n").filter(l => l.trim())
  if (lines.length < 2) return { headers: [], rows: [] }
  const headers = lines[0].split(",").map(h => h.trim())
  const rows = lines.slice(1).map(line => {
    const vals = line.split(",").map(v => v.trim())
    const obj = {}
    headers.forEach((h, i) => { obj[h] = vals[i] || "" })
    return obj
  })
  return { headers, rows }
}

app.use(bodyParser.json())
app.use(session({
  secret: process.env.SESSION_SECRET || "smu-peer-eval-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}))

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next()
  return res.redirect("/login.html")
}

function requireProfessor(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === "professor") return next()
  return res.status(403).json({ message: "Professors only" })
}

function requireStudent(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === "student") return next()
  return res.status(403).json({ message: "Students only" })
}

// Redirect root based on role
app.get("/", (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect(req.session.user.role === "professor" ? "/dashboard.html" : "/evaluation.html")
  }
  res.redirect("/login.html")
})

// Protect pages
app.get("/dashboard.html", requireAuth, (req, res) => {
  if (req.session.user.role !== "professor") return res.redirect("/evaluation.html")
  res.sendFile(path.join(__dirname, "public", "dashboard.html"))
})

app.get("/evaluation.html", requireAuth, (req, res) => {
  if (req.session.user.role !== "student") return res.redirect("/dashboard.html")
  res.sendFile(path.join(__dirname, "public", "evaluation.html"))
})

app.get("/create-course.html", requireAuth, (req, res) => {
  if (req.session.user.role !== "professor") return res.redirect("/evaluation.html")
  res.sendFile(path.join(__dirname, "public", "create-course.html"))
})

app.get("/assign-course.html", requireAuth, (req, res) => {
  if (req.session.user.role !== "professor") return res.redirect("/evaluation.html")
  res.sendFile(path.join(__dirname, "public", "assign-course.html"))
})

// ===================== AUTH API =====================

// Login - checks both Professor and Student tables
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" })
  }

  try {
    // Check Professor table first - look up by email
    const [professors] = await pool.execute(
      "SELECT professorID, email, firstName, lastName, password FROM Professor WHERE email = ?",
      [email]
    )

    if (professors.length > 0) {
      const prof = professors[0]
      if (prof.password !== password) {
        return res.status(401).json({ message: "Invalid password" })
      }
      req.session.user = {
        id: prof.professorID,
        name: prof.firstName + " " + prof.lastName,
        email: prof.email,
        role: "professor"
      }
      return res.json({ message: "Login successful", role: "professor" })
    }

    // Check Student table - look up by email
    const [students] = await pool.execute(
      "SELECT studentID, email, firstName, lastName, password FROM Student WHERE email = ?",
      [email]
    )

    if (students.length > 0) {
      const stu = students[0]
      if (stu.password !== password) {
        return res.status(401).json({ message: "Invalid password" })
      }
      req.session.user = {
        id: stu.studentID,
        name: stu.firstName + " " + stu.lastName,
        email: stu.email,
        role: "student"
      }
      return res.json({ message: "Login successful", role: "student" })
    }

    return res.status(401).json({ message: "Invalid email address" })
  } catch (err) {
    console.error("Login error:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get current user
app.get("/api/me", (req, res) => {
  if (req.session && req.session.user) return res.json(req.session.user)
  res.status(401).json({ message: "Not authenticated" })
})

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" })
  })
})

// Password validation helper
function validatePassword(password) {
  if (password.length < 8) return "Password must be at least 8 characters"
  if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter"
  if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter"
  if (!/[0-9]/.test(password)) return "Password must contain at least one number"
  return null
}

// Signup - create a new Student or Professor account
app.post("/api/signup", async (req, res) => {
  const { role, firstName, lastName, email, password } = req.body

  if (!role || !firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: "All fields are required" })
  }

  const pwError = validatePassword(password)
  if (pwError) return res.status(400).json({ message: pwError })

  try {
    // Check BOTH tables for duplicate email
    const [existingStudents] = await pool.execute("SELECT studentID FROM Student WHERE email = ?", [email])
    const [existingProfs] = await pool.execute("SELECT professorID FROM Professor WHERE email = ?", [email])
    if (existingStudents.length > 0 || existingProfs.length > 0) {
      return res.status(409).json({ message: "An account with this email already exists" })
    }

    if (role === "student") {
      const { studentNumber, year } = req.body
      await pool.execute(
        "INSERT INTO Student (email, firstName, lastName, studentNumber, year, password) VALUES (?, ?, ?, ?, ?, ?)",
        [email, firstName, lastName, studentNumber || null, year || null, password]
      )
      return res.json({ message: "Student account created" })

    } else if (role === "professor") {
      const { professorNumber } = req.body
      await pool.execute(
        "INSERT INTO Professor (email, firstName, lastName, professorNumber, password) VALUES (?, ?, ?, ?, ?)",
        [email, firstName, lastName, professorNumber || null, password]
      )
      return res.json({ message: "Professor account created" })

    } else {
      return res.status(400).json({ message: "Invalid role" })
    }
  } catch (err) {
    console.error("Signup error:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Reset password - find account by email and update password
app.post("/api/reset-password", async (req, res) => {
  const { email, newPassword } = req.body

  if (!email || !newPassword) {
    return res.status(400).json({ message: "Email and new password are required" })
  }

  const pwError = validatePassword(newPassword)
  if (pwError) return res.status(400).json({ message: pwError })

  try {
    // Check Professor table
    const [professors] = await pool.execute("SELECT professorID FROM Professor WHERE email = ?", [email])
    if (professors.length > 0) {
      await pool.execute("UPDATE Professor SET password = ? WHERE email = ?", [newPassword, email])
      return res.json({ message: "Password reset successfully" })
    }

    // Check Student table
    const [students] = await pool.execute("SELECT studentID FROM Student WHERE email = ?", [email])
    if (students.length > 0) {
      await pool.execute("UPDATE Student SET password = ? WHERE email = ?", [newPassword, email])
      return res.json({ message: "Password reset successfully" })
    }

    return res.status(404).json({ message: "No account found with this email" })
  } catch (err) {
    console.error("Reset password error:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// ===================== PROFESSOR API =====================

// Get all courses for this professor
app.get("/api/courses", requireAuth, requireProfessor, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT * FROM Course WHERE professorID = ?",
      [req.session.user.id]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching courses:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Create a new course
app.post("/api/courses", requireAuth, requireProfessor, async (req, res) => {
  const { courseName, courseNumber, semester, year } = req.body
  try {
    // Check for duplicate course number for this professor
    const [existing] = await pool.execute(
      "SELECT courseID FROM Course WHERE courseNumber = ? AND professorID = ?",
      [courseNumber, req.session.user.id]
    )
    if (existing.length > 0) {
      return res.status(409).json({ message: "A course with this course number already exists" })
    }

    const [result] = await pool.execute(
      "INSERT INTO Course (courseName, courseNumber, semester, year, professorID) VALUES (?, ?, ?, ?, ?)",
      [courseName, courseNumber, semester, year, req.session.user.id]
    )
    res.json({ courseID: result.insertId, message: "Course created" })
  } catch (err) {
    console.error("Error creating course:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Delete a course
app.delete("/api/courses/:courseID", requireAuth, requireProfessor, async (req, res) => {
  try {
    // Remove enrollments first, then delete the course
    await pool.execute("DELETE FROM Course_Enrollments WHERE courseID = ?", [req.params.courseID])
    await pool.execute("DELETE FROM Course WHERE courseID = ? AND professorID = ?", [req.params.courseID, req.session.user.id])
    res.json({ message: "Course deleted" })
  } catch (err) {
    console.error("Error deleting course:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get all students (for enrollment dropdown)
app.get("/api/students", requireAuth, requireProfessor, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT studentID, email, firstName, lastName, studentNumber, year FROM Student"
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching students:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get enrollments for a course
app.get("/api/courses/:courseID/enrollments", requireAuth, requireProfessor, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT ce.enrollmentID, ce.enrollmentDate, ce.studentID, ce.courseID,
              s.firstName, s.lastName, s.email, s.studentNumber
       FROM Course_Enrollments ce
       JOIN Student s ON ce.studentID = s.studentID
       WHERE ce.courseID = ?`,
      [req.params.courseID]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching enrollments:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Enroll a student in a course
app.post("/api/courses/:courseID/enrollments", requireAuth, requireProfessor, async (req, res) => {
  const { studentID } = req.body
  try {
    // Check for duplicate enrollment
    const [existing] = await pool.execute(
      "SELECT enrollmentID FROM Course_Enrollments WHERE studentID = ? AND courseID = ?",
      [studentID, req.params.courseID]
    )
    if (existing.length > 0) {
      return res.status(409).json({ message: "Student already enrolled in course" })
    }

    await pool.execute(
      "INSERT INTO Course_Enrollments (enrollmentDate, studentID, courseID) VALUES (NOW(), ?, ?)",
      [studentID, req.params.courseID]
    )
    res.json({ message: "Student enrolled" })
  } catch (err) {
    console.error("Error enrolling student:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Remove enrollment
app.delete("/api/enrollments/:enrollmentID", requireAuth, requireProfessor, async (req, res) => {
  try {
    await pool.execute("DELETE FROM Course_Enrollments WHERE enrollmentID = ?", [req.params.enrollmentID])
    res.json({ message: "Enrollment removed" })
  } catch (err) {
    console.error("Error removing enrollment:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get courses with enrollment counts and eval counts for dashboard
app.get("/api/dashboard/courses", requireAuth, requireProfessor, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT c.courseID, c.courseName, c.courseNumber, c.semester, c.year,
              COUNT(DISTINCT ce.studentID) AS enrolledCount,
              COUNT(DISTINCT pe.evaluationID) AS evalsCompleted
       FROM Course c
       LEFT JOIN Course_Enrollments ce ON c.courseID = ce.courseID
       LEFT JOIN Assignment a ON a.courseID = c.courseID
       LEFT JOIN Peer_Evaluation pe ON pe.assignmentID = a.assignmentID
       WHERE c.professorID = ?
       GROUP BY c.courseID`,
      [req.session.user.id]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching dashboard courses:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get recent evaluations across all professor's courses
app.get("/api/dashboard/recent-evaluations", requireAuth, requireProfessor, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT DISTINCT pe.evaluationID, pe.dateSubmitted, pe.contributesToTeam, pe.facilitatesContribution,
              pe.planningAndManaging, pe.fostersTeamEnvironment, pe.managesConflict,
              pe.overall, pe.comments,
              s.firstName AS evaluatedFirst, s.lastName AS evaluatedLast,
              COALESCE(c1.courseName, c2.courseName) AS courseName,
              COALESCE(c1.courseNumber, c2.courseNumber) AS courseNumber
       FROM Peer_Evaluation pe
       JOIN Student s ON pe.evaluatedID = s.studentID
       LEFT JOIN Assignment a ON pe.assignmentID = a.assignmentID
       LEFT JOIN Course c1 ON a.courseID = c1.courseID
       LEFT JOIN Course_Enrollments ce ON ce.studentID = pe.evaluatorID
       LEFT JOIN Course c2 ON ce.courseID = c2.courseID AND c2.professorID = ?
       WHERE c1.professorID = ? OR c2.professorID = ?
       ORDER BY pe.dateSubmitted DESC
       LIMIT 20`,
      [req.session.user.id, req.session.user.id, req.session.user.id]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching recent evaluations:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get course details (for popup) including enrolled students
app.get("/api/courses/:courseID/details", requireAuth, requireProfessor, async (req, res) => {
  try {
    const [courses] = await pool.execute(
      "SELECT * FROM Course WHERE courseID = ? AND professorID = ?",
      [req.params.courseID, req.session.user.id]
    )
    if (courses.length === 0) return res.status(404).json({ message: "Course not found" })

    const [students] = await pool.execute(
      `SELECT s.studentID, s.firstName, s.lastName, s.email, s.studentNumber
       FROM Course_Enrollments ce
       JOIN Student s ON ce.studentID = s.studentID
       WHERE ce.courseID = ?`,
      [req.params.courseID]
    )

    res.json({ course: courses[0], students })
  } catch (err) {
    console.error("Error fetching course details:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Enroll a student by details (manual add from assign-course page)
app.post("/api/courses/:courseID/enroll-manual", requireAuth, requireProfessor, async (req, res) => {
  const { firstName, lastName, studentNumber, email } = req.body
  if (!firstName || !lastName || !email) {
    return res.status(400).json({ message: "First name, last name, and email are required" })
  }
  if (!studentNumber || !studentNumber.trim()) {
    return res.status(400).json({ message: "Student ID is required" })
  }

  try {
    // Find or create student
    let [existing] = await pool.execute("SELECT studentID FROM Student WHERE email = ?", [email])
    let studentID

    if (existing.length > 0) {
      studentID = existing[0].studentID
      // Always update studentNumber
      await pool.execute("UPDATE Student SET studentNumber = ? WHERE studentID = ?", [studentNumber, studentID])
    } else {
      // Create a student stub (no password - they can sign up later)
      const [result] = await pool.execute(
        "INSERT INTO Student (email, firstName, lastName, studentNumber, password) VALUES (?, ?, ?, ?, ?)",
        [email, firstName, lastName, studentNumber, "Temp1234"]
      )
      studentID = result.insertId
    }

    // Check if already enrolled
    const [enrolled] = await pool.execute(
      "SELECT enrollmentID FROM Course_Enrollments WHERE studentID = ? AND courseID = ?",
      [studentID, req.params.courseID]
    )
    if (enrolled.length > 0) {
      return res.status(409).json({ message: "Student is already enrolled in this course" })
    }

    await pool.execute(
      "INSERT INTO Course_Enrollments (enrollmentDate, studentID, courseID) VALUES (NOW(), ?, ?)",
      [studentID, req.params.courseID]
    )
    res.json({ message: "Student enrolled successfully" })
  } catch (err) {
    console.error("Error enrolling student manually:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Import students from CSV and enroll them in a course (assign-course page)
app.post("/api/courses/:courseID/import-students", requireAuth, requireProfessor, csvUpload.single("csv"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No CSV file uploaded" })

  const { headers, rows } = parseCSV(req.file.buffer)
  const required = ["firstName", "lastName", "email", "studentNumber"]
  const missing = required.filter(h => !headers.includes(h))
  if (missing.length > 0) {
    return res.status(400).json({ message: "Missing required columns: " + missing.join(", ") })
  }

  let enrolled = 0
  const errors = []

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]
    try {
      if (!r.firstName || !r.lastName || !r.email || !r.studentNumber) {
        errors.push({ row: i + 2, message: "Missing required fields" })
        continue
      }

      // Find or create student by email
      let [existing] = await pool.execute("SELECT studentID FROM Student WHERE email = ?", [r.email])
      let studentID

      if (existing.length > 0) {
        studentID = existing[0].studentID
        // Always update studentNumber from CSV
        await pool.execute("UPDATE Student SET studentNumber = ? WHERE studentID = ?", [r.studentNumber, studentID])
      } else {
        // Create student stub with password from CSV or default
        const pw = r.password || "Temp1234"
        const [result] = await pool.execute(
          "INSERT INTO Student (email, firstName, lastName, studentNumber, year, password) VALUES (?, ?, ?, ?, ?, ?)",
          [r.email, r.firstName, r.lastName, r.studentNumber, r.year || null, pw]
        )
        studentID = result.insertId
      }

      // Check for duplicate enrollment
      const [enrolledCheck] = await pool.execute(
        "SELECT enrollmentID FROM Course_Enrollments WHERE studentID = ? AND courseID = ?",
        [studentID, req.params.courseID]
      )
      if (enrolledCheck.length > 0) {
        errors.push({ row: i + 2, message: "Student already enrolled in course: " + r.email })
        continue
      }

      await pool.execute(
        "INSERT INTO Course_Enrollments (enrollmentDate, studentID, courseID) VALUES (NOW(), ?, ?)",
        [studentID, req.params.courseID]
      )
      enrolled++
    } catch (err) {
      errors.push({ row: i + 2, message: err.message })
    }
  }

  res.json({ enrolled, total: rows.length, errors })
})

// ===================== BATCH IMPORT API =====================

// Batch import students from CSV
app.post("/api/batch/students", requireAuth, requireProfessor, csvUpload.single("csv"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No CSV file uploaded" })

  const { headers, rows } = parseCSV(req.file.buffer)
  const required = ["firstName", "lastName", "email", "password"]
  const missing = required.filter(h => !headers.includes(h))
  if (missing.length > 0) {
    return res.status(400).json({ message: "Missing required columns: " + missing.join(", ") })
  }

  let imported = 0
  const errors = []

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]
    try {
      if (!r.firstName || !r.lastName || !r.email || !r.password) {
        errors.push({ row: i + 2, message: "Missing required fields" })
        continue
      }
      const pwError = validatePassword(r.password)
      if (pwError) { errors.push({ row: i + 2, message: pwError }); continue }

      const [existing] = await pool.execute("SELECT studentID FROM Student WHERE email = ?", [r.email])
      if (existing.length > 0) { errors.push({ row: i + 2, message: "Email already exists: " + r.email }); continue }

      await pool.execute(
        "INSERT INTO Student (email, firstName, lastName, studentNumber, year, password) VALUES (?, ?, ?, ?, ?, ?)",
        [r.email, r.firstName, r.lastName, r.studentNumber || null, r.year || null, r.password]
      )
      imported++
    } catch (err) {
      errors.push({ row: i + 2, message: err.message })
    }
  }

  res.json({ imported, total: rows.length, errors })
})

// Batch import courses from CSV
app.post("/api/batch/courses", requireAuth, requireProfessor, csvUpload.single("csv"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No CSV file uploaded" })

  const { headers, rows } = parseCSV(req.file.buffer)
  const required = ["courseName", "courseNumber", "semester", "year"]
  const missing = required.filter(h => !headers.includes(h))
  if (missing.length > 0) {
    return res.status(400).json({ message: "Missing required columns: " + missing.join(", ") })
  }

  let imported = 0
  const errors = []

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]
    try {
      if (!r.courseName || !r.courseNumber || !r.semester || !r.year) {
        errors.push({ row: i + 2, message: "Missing required fields" })
        continue
      }
      const [existingCourse] = await pool.execute(
        "SELECT courseID FROM Course WHERE courseNumber = ? AND professorID = ?",
        [r.courseNumber, req.session.user.id]
      )
      if (existingCourse.length > 0) {
        errors.push({ row: i + 2, message: "Course already exists: " + r.courseNumber })
        continue
      }
      await pool.execute(
        "INSERT INTO Course (courseName, courseNumber, semester, year, professorID) VALUES (?, ?, ?, ?, ?)",
        [r.courseName, r.courseNumber, r.semester, parseInt(r.year), req.session.user.id]
      )
      imported++
    } catch (err) {
      errors.push({ row: i + 2, message: err.message })
    }
  }

  res.json({ imported, total: rows.length, errors })
})

// Batch import enrollments from CSV
app.post("/api/batch/enrollments", requireAuth, requireProfessor, csvUpload.single("csv"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No CSV file uploaded" })

  const { headers, rows } = parseCSV(req.file.buffer)
  const required = ["studentEmail", "courseNumber"]
  const missing = required.filter(h => !headers.includes(h))
  if (missing.length > 0) {
    return res.status(400).json({ message: "Missing required columns: " + missing.join(", ") })
  }

  let imported = 0
  const errors = []

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]
    try {
      if (!r.studentEmail || !r.courseNumber) {
        errors.push({ row: i + 2, message: "Missing required fields" })
        continue
      }

      // Look up student by email
      const [students] = await pool.execute("SELECT studentID FROM Student WHERE email = ?", [r.studentEmail])
      if (students.length === 0) { errors.push({ row: i + 2, message: "Student not found: " + r.studentEmail }); continue }

      // Look up course by number (owned by this professor)
      const [courses] = await pool.execute(
        "SELECT courseID FROM Course WHERE courseNumber = ? AND professorID = ?",
        [r.courseNumber, req.session.user.id]
      )
      if (courses.length === 0) { errors.push({ row: i + 2, message: "Course not found: " + r.courseNumber }); continue }

      // Check if already enrolled
      const [existing] = await pool.execute(
        "SELECT enrollmentID FROM Course_Enrollments WHERE studentID = ? AND courseID = ?",
        [students[0].studentID, courses[0].courseID]
      )
      if (existing.length > 0) { errors.push({ row: i + 2, message: "Already enrolled" }); continue }

      await pool.execute(
        "INSERT INTO Course_Enrollments (enrollmentDate, studentID, courseID) VALUES (NOW(), ?, ?)",
        [students[0].studentID, courses[0].courseID]
      )
      imported++
    } catch (err) {
      errors.push({ row: i + 2, message: err.message })
    }
  }

  res.json({ imported, total: rows.length, errors })
})

// ===================== STUDENT API =====================

// Get courses the student is enrolled in
app.get("/api/my-courses", requireAuth, requireStudent, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT c.courseID, c.courseName, c.courseNumber, c.semester, c.year
       FROM Course_Enrollments ce
       JOIN Course c ON ce.courseID = c.courseID
       WHERE ce.studentID = ?`,
      [req.session.user.id]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching student courses:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get team members for a course (group mates, or all enrolled students if no groups)
app.get("/api/courses/:courseID/team-members", requireAuth, requireStudent, async (req, res) => {
  try {
    // Try group-based lookup first
    const [members] = await pool.execute(
      `SELECT DISTINCT s.studentID, s.firstName, s.lastName, s.email
       FROM Group_Members gm
       JOIN \`Group\` g ON gm.groupID = g.groupID
       JOIN Course c ON g.courseID = c.courseID
       JOIN Group_Members gm2 ON gm2.groupID = gm.groupID
       JOIN Student s ON gm2.studentID = s.studentID
       WHERE g.courseID = ? AND gm.studentID = ? AND gm2.studentID != ?`,
      [req.params.courseID, req.session.user.id, req.session.user.id]
    )

    // Fall back to all enrolled students in the course if no groups exist
    if (members.length === 0) {
      const [enrolled] = await pool.execute(
        `SELECT DISTINCT s.studentID, s.firstName, s.lastName, s.email
         FROM Course_Enrollments ce
         JOIN Student s ON ce.studentID = s.studentID
         WHERE ce.courseID = ? AND ce.studentID != ?`,
        [req.params.courseID, req.session.user.id]
      )
      return res.json(enrolled)
    }

    res.json(members)
  } catch (err) {
    console.error("Error fetching team members:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get assignments for a course
app.get("/api/courses/:courseID/assignments", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT * FROM Assignment WHERE courseID = ? AND closeDate >= NOW()",
      [req.params.courseID]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching assignments:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Submit a peer evaluation
app.post("/api/evaluations", requireAuth, requireStudent, async (req, res) => {
  const { contributesToTeam, facilitatesContribution,
          planningAndManaging, fostersTeamEnvironment, managesConflict, comments } = req.body

  // Convert empty strings to null for nullable FK columns
  const assignmentID = req.body.assignmentID || null
  const evaluatedID = req.body.evaluatedID || null
  const groupID = req.body.groupID || null

  if (!evaluatedID) {
    return res.status(400).json({ message: "Please select a team member to evaluate" })
  }

  const overall = Number(contributesToTeam) + Number(facilitatesContribution) +
                  Number(planningAndManaging) + Number(fostersTeamEnvironment) + Number(managesConflict)

  try {
    await pool.execute(
      `INSERT INTO Peer_Evaluation
       (dateSubmitted, isSubmitted, contributesToTeam, facilitatesContribution,
        planningAndManaging, fostersTeamEnvironment, managesConflict, overall,
        comments, assignmentID, evaluatorID, evaluatedID, groupID)
       VALUES (NOW(), TRUE, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [contributesToTeam, facilitatesContribution, planningAndManaging,
       fostersTeamEnvironment, managesConflict, overall, comments,
       assignmentID, req.session.user.id, evaluatedID, groupID]
    )
    res.json({ message: "Evaluation submitted" })
  } catch (err) {
    console.error("Error submitting evaluation:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get all peer evaluations received by this student
app.get("/api/my-feedback", requireAuth, requireStudent, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT pe.evaluationID, pe.dateSubmitted, pe.contributesToTeam, pe.facilitatesContribution,
              pe.planningAndManaging, pe.fostersTeamEnvironment, pe.managesConflict,
              pe.overall, pe.comments,
              c.courseNumber, c.courseName,
              a.title AS assignmentTitle
       FROM Peer_Evaluation pe
       LEFT JOIN Assignment a ON pe.assignmentID = a.assignmentID
       LEFT JOIN Course c ON a.courseID = c.courseID
       WHERE pe.evaluatedID = ?
       ORDER BY pe.dateSubmitted DESC`,
      [req.session.user.id]
    )
    res.json(rows)
  } catch (err) {
    console.error("Error fetching feedback:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Get team members across all courses for this student
app.get("/api/my-team-members", requireAuth, requireStudent, async (req, res) => {
  try {
    // Get group-based team members
    const [groupMembers] = await pool.execute(
      `SELECT DISTINCT s.studentID, s.firstName, s.lastName, s.email,
              c.courseNumber, c.courseName, g.groupName
       FROM Group_Members gm
       JOIN \`Group\` g ON gm.groupID = g.groupID
       JOIN Course c ON g.courseID = c.courseID
       JOIN Group_Members gm2 ON gm2.groupID = gm.groupID
       JOIN Student s ON gm2.studentID = s.studentID
       WHERE gm.studentID = ? AND gm2.studentID != ?`,
      [req.session.user.id, req.session.user.id]
    )

    // If no groups, fall back to all co-enrolled students
    if (groupMembers.length === 0) {
      const [enrolled] = await pool.execute(
        `SELECT DISTINCT s.studentID, s.firstName, s.lastName, s.email,
                c.courseNumber, c.courseName, NULL AS groupName
         FROM Course_Enrollments ce
         JOIN Course c ON ce.courseID = c.courseID
         JOIN Course_Enrollments ce2 ON ce2.courseID = ce.courseID
         JOIN Student s ON ce2.studentID = s.studentID
         WHERE ce.studentID = ? AND ce2.studentID != ?`,
        [req.session.user.id, req.session.user.id]
      )
      return res.json(enrolled)
    }

    res.json(groupMembers)
  } catch (err) {
    console.error("Error fetching team members:", err)
    res.status(500).json({ message: "Server error" })
  }
})

// Static files (after protected routes)
app.use(express.static(path.join(__dirname, "public")))

// Webhook route
app.use("/webhook", webhookRouter)

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))