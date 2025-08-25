// utils/emailService.js
const nodemailer = require('nodemailer');

// Create transporter
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// OTP email template
const sendOTPEmail = async (to, context) => {
    const { name, otp, website, company, expiration, purpose = 'verification' } = context;

    const subject = purpose === 'password_reset'
        ? `Password Reset Request - ${company}`
        : `Your Verification Code - ${company}`;

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
        .content { background-color: #fff; padding: 30px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .otp { font-size: 32px; font-weight: bold; text-align: center; margin: 30px 0; color: #007bff; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6c757d; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>${company}</h1>
        </div>
        <div class="content">
          <h2>Hello ${name},</h2>
          <p>Your ${purpose} code for ${website} is:</p>
          <div class="otp">${otp}</div>
          <p>This code will expire in ${expiration} minutes. Please do not share this code with anyone.</p>
          <p>If you didn't request this ${purpose}, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; ${new Date().getFullYear()} ${company}. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to,
            subject,
            html
        });

        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
};

// Welcome email template
const sendWelcomeEmail = async (to, context) => {
    const { name, website, company } = context;

    const subject = `Welcome to ${company}!`;

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
        .content { background-color: #fff; padding: 30px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6c757d; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>${company}</h1>
        </div>
        <div class="content">
          <h2>Welcome ${name}!</h2>
          <p>Thank you for registering with ${company}. We're excited to have you on board!</p>
          <p>You can now access all features of ${website} using your account.</p>
          <p>If you have any questions, please don't hesitate to contact our support team.</p>
        </div>
        <div class="footer">
          <p>&copy; ${new Date().getFullYear()} ${company}. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to,
            subject,
            html
        });

        return true;
    } catch (error) {
        console.error('Error sending welcome email:', error);
        return false;
    }
};

module.exports = {
    sendOTPEmail,
    sendWelcomeEmail,
    transporter
};