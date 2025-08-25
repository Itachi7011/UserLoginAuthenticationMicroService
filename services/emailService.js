// services/emailService.js
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Generate OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

// Email transporter
const createTransporter = () => {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
};

// Professional email templates
const emailTemplates = {
  otpVerification: (clientName, companyName, otp, expiration) => ({
    subject: `Verify Your ${companyName} Account - OTP Required`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 5px 5px; }
          .otp-code { 
            background: #ffffff; 
            border: 2px dashed #2563eb; 
            padding: 15px; 
            text-align: center; 
            font-size: 24px; 
            font-weight: bold; 
            letter-spacing: 5px; 
            margin: 20px 0; 
          }
          .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6b7280; }
          .warning { color: #dc2626; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${companyName}</h1>
          </div>
          <div class="content">
            <h2>Email Verification Required</h2>
            <p>Dear ${clientName},</p>
            <p>Thank you for registering with ${companyName}. To complete your account setup and ensure the security of your information, please verify your email address using the One-Time Password (OTP) below:</p>
            
            <div class="otp-code">${otp}</div>
            
            <p class="warning">⚠️ This OTP will expire in ${expiration} minutes. Please do not share this code with anyone.</p>
            
            <p>If you did not create an account with ${companyName}, please ignore this email or contact our support team immediately.</p>
            
            <p>Best regards,<br>The ${companyName} Team</p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>© ${new Date().getFullYear()} ${companyName}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  }),
  welcome: (clientName, companyName) => ({
    subject: `Welcome to ${companyName}! Your Account is Ready`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #10b981; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 5px 5px; }
          .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6b7280; }
          .button { background: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to ${companyName}!</h1>
          </div>
          <div class="content">
            <h2>Your Account is Ready</h2>
            <p>Dear ${clientName},</p>
            <p>Congratulations! Your account with ${companyName} has been successfully created and verified.</p>
            
            <p>You can now access your dashboard and start using our services:</p>
            
            <p style="text-align: center; margin: 30px 0;">
              <a href="${process.env.CLIENT_URL || 'http://localhost:5173'}/login" class="button">Login to Your Account</a>
            </p>
            
            <p><strong>Next Steps:</strong></p>
            <ul>
              <li>Complete your profile information</li>
              <li>Explore our API documentation</li>
              <li>Set up your authentication endpoints</li>
              <li>Configure your application settings</li>
            </ul>
            
            <p>If you need any assistance, please don't hesitate to contact our support team.</p>
            
            <p>Best regards,<br>The ${companyName} Team</p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>© ${new Date().getFullYear()} ${companyName}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  })
};

// Send email function
const sendEmail = async (to, subject, html) => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.SMTP_FROM || `"${process.env.APP_NAME}" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html
    };

    const result = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', result.messageId);
    return { success: true, messageId: result.messageId };
  } catch (error) {
    console.error('Error sending email:', error);
    return { success: false, error: error.message };
  }
};

// Send OTP email
const sendOTPEmail = async (email, clientName, companyName, otp, expiration) => {
  const template = emailTemplates.otpVerification(clientName, companyName, otp, expiration);
  return await sendEmail(email, template.subject, template.html);
};

// Send welcome email
const sendWelcomeEmail = async (email, clientName, companyName) => {
  const template = emailTemplates.welcome(clientName, companyName);
  return await sendEmail(email, template.subject, template.html);
};

module.exports = {
  generateOTP,
  sendOTPEmail,
  sendWelcomeEmail,
  sendEmail
};