// Webhook to receive data from form and insert to database
const express = require("express")
const { insertDB } = require("./functions")

const router = express.Router()

router.post("/", async (req, res) => {
  console.log("webhook received:", req.body)

  // Calls insertDB function
  const success = await insertDB(req.body)

  if (success) {
    res.status(200).end()
  } else {
    res.status(500).end()
  }
})

module.exports = router