// Function to send activation email
async function sendActivationEmail(email, activationToken) {
  // Logic to send the activation email
  // You can use an email service like Nodemailer or a third-party API

  // Example using Nodemailer:
  const nodemailer = require('nodemailer');
  const activationURL = `${process.env.BASE_URL}:${process.env.PORT}/auth/activate?token=${activationToken}`;

  // Email transport configuration
  const transporter = nodemailer.createTransport({
    host: 'domain.com.br', // SMTP server
    port: 465, // SMTP server port
    secure: true, // Defines if the connection is secure (true for TLS or false for non-TLS)
    auth: {
      user: 'noreply@domain.com.br', // Your email address
      pass: 'Password' // Your email password
    }
  });

  // Configure email content
  const mailOptions = {
    from: 'noreply@domain.com', // Sender email address
    to: email, // Recipient email address
    subject: 'Account Activation', // Email subject
    text: `Hello! Click the following link to activate your account: ${activationURL}` // Email body
  };

  // Send the email
  await transporter.sendMail(mailOptions);
}

// Function to generate an activation token
function generateActivationToken() {
  // Logic to generate an activation token
  // You can use a library like uuid or generate a random code

  // Example using the uuid library:
  const { v4: uuidv4 } = require('uuid');
  const activationToken = uuidv4();

  return activationToken;
}

module.exports = {
  sendActivationEmail,
  generateActivationToken
};
