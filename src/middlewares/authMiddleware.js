const jwt = require('jsonwebtoken')
const { connect } = require('../config/db')
const { ObjectId } = require('mongodb')

async function returnUserDataToken (req, res, next) {
  const token = req.headers.authorization

  if (!token || !token.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de autenticação não fornecido.' })
  }

  try {
    const tokenWithoutBearer = token.slice(7)
    const db = await connect()
    const collection = db.collection('users')
    const decoded = jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET)
    const userId = new ObjectId(decoded.userId)
    const user = await collection.findOne({ _id: userId })

    if (!user) {
      return res.status(401).json({ error: 'Token de autenticação inválido.' })
    }

    const userData = {
      id: user._id,
      name: user.name,
      email: user.email
    }

    req.userId = user._id
    req.userData = userData
    next()
  } catch (error) {
    return res.status(401).json({ error: 'Token de autenticação inválido.' })
  }
}

async function verifyToken (req, res, next) {
  const token = req.headers.authorization

  if (!token || !token.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de autenticação não fornecido.' })
  }

  try {
    const tokenWithoutBearer = token.slice(7)
    const db = await connect()
    const collection = db.collection('users')
    const decoded = jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET)
    const userId = new ObjectId(decoded.userId)
    const user = await collection.findOne({ _id: userId })

    if (!user) {
      return res.status(401).json({ error: 'Token de autenticação inválido.' })
    }

    req.userId = user._id
    next()
  } catch (error) {
    return res.status(401).json({ error: 'Token de autenticação inválido.' })
  }
}

module.exports = {
  verifyToken,
  returnUserDataToken
}
