# Api Node Express

## Table of Contents
- [Description](#description)
- [Project Setup](#project-setup)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the Project](#running-the-project)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Endpoints](#endpoints)
  - [Auth](#auth)
  - [Protected](#protected)
- [Examples of Use](#examples-of-use)
- [Contributing](#contributing)
- [License](#license)

## Description
This project is a starter sample in Node.js for other developers to begin their projects. It provides an API for user authentication and management, including Swagger documentation. The API utilizes MongoDB for data storage and JWT for authentication.

## Project Setup

### Dependencies
- ![express](https://img.shields.io/badge/express-v4.17.1-blue)
- ![mongodb](https://img.shields.io/badge/mongodb-v4.0.0-green)
- ![jsonwebtoken](https://img.shields.io/badge/jsonwebtoken-v8.5.1-orange)
- ![bcrypt](https://img.shields.io/badge/bcrypt-v5.0.1-yellow)
- ![yup](https://img.shields.io/badge/yup-v0.32.9-lightgrey)
- ![swagger-jsdoc](https://img.shields.io/badge/swagger--jsdoc-v7.0.0-yellowgreen)
- ![swagger-ui-express](https://img.shields.io/badge/swagger--ui--express-v4.1.6-red)
- ![dotenv](https://img.shields.io/badge/dotenv-v10.0.0-blueviolet)
- ![cors](https://img.shields.io/badge/cors-v2.8.5-brightgreen)
- ![module-alias](https://img.shields.io/badge/module--alias-v2.2.2-critical)

### Installation
Clone the repository: https://github.com/LuizEduPP/starter-api-node.git

Navigate to the project directory:
cd starter-api-node

Install dependencies:
yarn

### Configuration
Create a .env file in the project root and add the following environment variables:

```env
MONGODB_URI=<your_mongodb_uri>
JWT_SECRET=<your_jwt_secret>
REFRESH_TOKEN_SECRET=<your_refresh_token_secret>
BASE_URL=<base_url>
PORT=<server_port>
```

### Running the Project
To start the server, use the command:
yarn start or yarn dev

The server will be available at `http://localhost:<server_port>`.

## Project Structure

- `config/db.js`: Configuration and connection to MongoDB.
- `docs/swagger.js`: Swagger documentation configuration.
- `middlewares/authMiddleware.js`: Authentication middlewares using JWT.
- `routes/auth.js`: Authentication routes.
- `routes/protected.js`: Protected routes.
- `utils/email.js`: Utility functions for sending emails.

## Documentation
API documentation is available at `http://localhost:<server_port>`.

## Endpoints

### Auth
- `POST /auth/login`: User login.
- `POST /auth/register`: Register a new user.
- `GET /auth/activate`: Activate user account via activation token.
- `PUT /auth/update`: Update user data.
- `POST /auth/reset-password`: Reset user password.

### Protected
Protected routes requiring JWT authentication:

- `GET /user`: Test user authentication.
- `GET /user/me`: Get current user data.
- `GET /user/key`: Generate and retrieve a new JWT secret key.

## Examples of Use (see all in server /)

### Auth Endpoints

#### Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```


#### Reset Password
```http
POST /auth/reset-password
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "userId": "5f6a9b4d50f64d001cefc09a",
  "oldPassword": "password123",
  "newPassword": "newPassword123"
}
```
#### Register
```http
POST /auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "newuser@example.com",
  "password": "password123"
}
```

#### Test User Authentication

**Request:**
```http
GET /user
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

```http
GET /user/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Contributing
Contributions are welcome! Feel free to open issues and pull requests.

## License
This project is licensed under the MIT License.