const { MongoClient } = require('mongodb')
require('dotenv').config()

const uri = process.env.MONGODB_URI
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true })

async function connect () {
  try {
    await client.connect()

    return client.db()
  } catch (error) {
    console.error('Error connecting to database:', error)
    throw error
  }
}

module.exports = { connect }
