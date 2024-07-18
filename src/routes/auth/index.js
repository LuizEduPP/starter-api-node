const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const yup = require('yup');
const { ObjectId } = require('mongodb');
const { connect } = require('../../config/db');
const { verifyToken } = require('@middlewares/authMiddleware');
const { sendActivationEmail, generateActivationToken } = require('@utils/email');

const loginSchema = yup.object().shape({
  email: yup.string().required(),
  password: yup.string().required()
});

const registerSchema = yup.object().shape({
  name: yup.string().required(),
  email: yup.string().required(),
  password: yup.string().min(6).required()
});

const updateSchema = yup.object().shape({
  userId: yup.string().required(),
  name: yup.string().required(),
  email: yup.string().required()
});

const resetPasswordSchema = yup.object().shape({
  userId: yup.string().required(),
  oldPassword: yup.string().required(),
  newPassword: yup.string().min(6).required()
});

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: API for authentication and user management
 */

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: User login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: User email
 *                 example: '123456'
 *               password:
 *                 type: string
 *                 description: User password
 *                 example: 'password123'
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                   description: JWT access token
 *                   example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
 *                 refreshToken:
 *                   type: string
 *                   description: JWT refresh token
 *                   example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
 *                 userData:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       description: User ID
 *                       example: '5f6a9b4d50f64d001cefc09a'
 *                     name:
 *                       type: string
 *                       description: User name
 *                       example: 'Dr. John Doe'
 *                     email:
 *                       type: string
 *                       description: User email
 *                       example: '123456'
 *       400:
 *         description: Validation error in request data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'email is required'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Incorrect password'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'User not found'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Error: Database connection error'
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    try {
      await loginSchema.validate(req.body);
    } catch (error) {
      return res.status(400).json({ message: error.message });
    }

    const db = await connect();
    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.status === 0) {
      return res.status(403).json({ message: 'Invalid user.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Incorrect password.' });
    }

    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

    const userData = {
      id: user._id,
      name: user.name,
      email: user.email
    };

    return res.status(200).json({ accessToken, refreshToken, userData });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error}` });
  }
});

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: User name
 *                 example: 'John Doe'
 *               email:
 *                 type: string
 *                 description: User email
 *                 example: 'test@example.com'
 *               password:
 *                 type: string
 *                 description: User password (minimum 6 characters)
 *                 example: 'password123'
 *     responses:
 *       200:
 *         description: User successfully registered
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'User successfully registered. Check your email to activate your account.'
 *       400:
 *         description: Validation error in request data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'email is required'
 *       409:
 *         description: Email conflict
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'A user with this email already exists.'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Error: Database connection error'
 */
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const db = await connect();
    const usersCollection = db.collection('users');

    const existingUser = await usersCollection.findOne({ email });

    try {
      await registerSchema.validate(req.body);
    } catch (message) {
      return res.status(400).json({ message: message.message });
    }

    if (existingUser) {
      return res.status(409).json({ message: 'A user with this email already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const activationToken = generateActivationToken();

    // Create the user
    const user = {
      name,
      email,
      password: hashedPassword,
      status: 0,
      activationToken
    };

    // Insert the user into the "users" collection
    await usersCollection.insertOne(user);

    await sendActivationEmail(email, activationToken);

    return res.status(200).json({ message: 'User successfully registered. Check your email to activate your account.' });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error}` });
  }
});

/**
 * @swagger
 * /auth/activate:
 *   get:
 *     summary: Activate user account through activation token
 *     tags: [Auth]
 *     parameters:
 *       - in: query
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Activation token sent by email
 *     responses:
 *       200:
 *         description: Account successfully activated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Account successfully activated.'
 *       400:
 *         description: Activation token not provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Activation token not provided.'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Invalid or expired activation token.'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Error: Database connection error'
 */
router.get('/activate', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: 'Activation token not provided.' });
  }

  const db = await connect();
  const usersCollection = db.collection('users');

  try {
    const user = await usersCollection.findOne({ activationToken: token });

    if (!user) {
      return res.status(404).json({ message: 'Invalid or expired activation token.' });
    }

    await usersCollection.updateOne({ _id: ObjectId(user._id) }, { $set: { status: 1, activationToken: null } });

    return res.status(200).json({ message: 'Account successfully activated.' });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error}` });
  }
});

/**
 * @swagger
 * /auth/update:
 *   put:
 *     summary: Update user data
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *                 description: User ID
 *                 example: '5f6a9b4d50f64d001cefc09a'
 *               name:
 *                 type: string
 *                 description: User name
 *                 example: 'John Doe'
 *               email:
 *                 type: string
 *                 description: User email
 *                 example: 'test@example.com'
 *     responses:
 *       200:
 *         description: User data successfully updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'User data successfully updated.'
 *       400:
 *         description: Validation error in request data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'email is required'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'User not found.'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Error: Database connection error'
 */
router.put('/update', verifyToken, async (req, res) => {
  const { userId, name, email } = req.body;

  try {
    await updateSchema.validate(req.body);
  } catch (message) {
    return res.status(400).json({ message: message.message });
  }

  const db = await connect();
  const usersCollection = db.collection('users');

  try {
    const user = await usersCollection.findOne({ _id: ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    await usersCollection.updateOne({ _id: ObjectId(userId) }, { $set: { name, email } });

    return res.status(200).json({ message: 'User data successfully updated.' });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error}` });
  }
});

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Reset user password
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *                 description: User ID
 *                 example: '5f6a9b4d50f64d001cefc09a'
 *               oldPassword:
 *                 type: string
 *                 description: Old password
 *                 example: 'oldPassword123'
 *               newPassword:
 *                 type: string
 *                 description: New password (minimum 6 characters)
 *                 example: 'newPassword123'
 *     responses:
 *       200:
 *         description: Password successfully reset
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Password successfully reset.'
 *       400:
 *         description: Validation error in request data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'oldPassword is required'
 *       401:
 *         description: Old password is incorrect
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Old password is incorrect.'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'User not found.'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 'Error: Database connection error'
 */
router.post('/reset-password', verifyToken, async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;

  try {
    await resetPasswordSchema.validate(req.body);
  } catch (message) {
    return res.status(400).json({ message: message.message });
  }

  const db = await connect();
  const usersCollection = db.collection('users');

  try {
    const user = await usersCollection.findOne({ _id: ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return res.status(401).json({ message: 'Old password is incorrect.' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await usersCollection.updateOne({ _id: ObjectId(userId) }, { $set: { password: hashedNewPassword } });

    return res.status(200).json({ message: 'Password successfully reset.' });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error}` });
  }
});

module.exports = router;
