// Functions for database operations
const pool = require("./db")

// Function to parse body and insert to database
async function insertDB(data) {
  try {
    const { dateSubmitted, contributesToTeam, facilitatesContribution, planningAndManaging, fostersTeamEnvironment, managesConflict, comments } = data

    const overall = (
      Number(contributesToTeam) +
      Number(facilitatesContribution) +
      Number(planningAndManaging) +
      Number(fostersTeamEnvironment) +
      Number(managesConflict)
    )

    await pool.execute(
      `INSERT INTO Peer_Evaluation (dateSubmitted, contributesToTeam, facilitatesContribution, planningAndManaging, fostersTeamEnvironment, managesConflict, comments, overall)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [dateSubmitted, contributesToTeam, facilitatesContribution, planningAndManaging, fostersTeamEnvironment, managesConflict, comments, overall]
    )

    console.log("Data inserted successfully")
    return true

  } catch (err) {
    console.error("Error inserting data:", err)
    return false
  }
}

module.exports = { insertDB }