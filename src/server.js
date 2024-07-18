const express = require('express');
const http = require('http');
const cors = require('cors');
const swaggerSetup = require('./docs/swagger');

require('dotenv').config();
require('module-alias/register');

// Server
const app = express();
const server = http.createServer(app);

// Middleware
app.use(express.json());

// CORS Configuration
app.use(
  cors({
    origin: [process.env.BASE_URL || 'http://localhost:8082'],
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.urlencoded({ extended: true }));

const authRoutes = require('@routes/auth');
const protectedRoutes = require('@routes/protected');

// Configuração do Swagger utilizando setupSwagger
swaggerSetup(app);

app.use('/auth', authRoutes);
app.use('/protected', protectedRoutes);

const hostname = process.env.BASE_URL || 'localhost';
const port = process.env.PORT || 8082;
server.listen(port, hostname, () => {
  console.log(`Server ${hostname} running on port ${port}`);
});
