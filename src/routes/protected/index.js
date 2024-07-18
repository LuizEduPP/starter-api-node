const express = require('express');
const router = express.Router();
const { verifyToken, returnUserDataToken } = require('@middlewares/authMiddleware');
const { connect } = require('../../config/db');

/**
 * @swagger
 * tags:
 *   name: User
 *   description: API for user-related operations
 */

/**
 * @swagger
 * /user:
 *   get:
 *     summary: Test user authentication
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successful authentication
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
router.get('/', verifyToken, (req, res) => {
  try {
    res.status(200).json();
  } catch (error) {
    return res.status(500).json();
  }
});

/**
 * @swagger
 * /user/me:
 *   get:
 *     summary: Get current user data
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved user data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userData:
 *                   type: object
 *                   description: Current user data
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
router.get('/me', returnUserDataToken, (req, res) => {
  try {
    const userData = req.userData;
    res.status(200).json({ userData });
  } catch (error) {
    return res.status(500).json({ message: 'Protected route error.' });
  }
});

/**
 * @swagger
 * /user/key:
 *   get:
 *     summary: Generate and retrieve a new JWT secret key
 *     tags: [User]
 *     responses:
 *       200:
 *         description: Successfully generated and retrieved JWT secret key
 *       500:
 *         description: Internal server error
 */
router.get('/key', async (req, res) => {
  const crypto = require('crypto');
  const jwtSecret = crypto.randomBytes(32).toString('hex');
  console.log(jwtSecret);
  res.status(200).json(jwtSecret);
});

module.exports = router;
