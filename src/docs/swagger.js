const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Api Node',
    version: '1.0.0',
    description: 'Api Node Documentation',
  },
  servers: [
    {
      url: process.env.BASE_URL || 'http://localhost:8082',
    },
  ],
};

const options = {
  swaggerDefinition,
  apis: [
    'routes/auth/*.js', 
    'src/routes/auth/*.js', 
    'routes/protected/*.js', 
    'src/routes/protected/*.js',
  ],
};

const swaggerSpec = swaggerJSDoc(options);

const setupSwagger = (app) => {
  app.use('/', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
};

module.exports = setupSwagger;
