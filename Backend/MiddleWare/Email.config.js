const nodemailer = require("nodemailer");
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Test the email connection
transporter.verify(function (error, success) {
  if (error) {
    console.log("Email connection error:", error);
  } else {
    console.log("Email server is ready to send messages");
  }
});

const SendEmail = async (to, verificationCode) => {
  try {
    const mailOptions = {
      from: `"VerifiedAuthority" <${process.env.EMAIL_USER}>`,
      to: to,  // Use the parameter passed in
      subject: "Email Verification Code",
      text: `Your verification code is: ${verificationCode}`,
      html: `
        <h2>Email Verification</h2>
        <p>Your verification code is:</p>
        <h1 style="color: blue; font-size: 32px; font-weight: bold;">${verificationCode}</h1>
        <p>Please enter this code to verify your email address.</p>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent successfully to:", to, "Message ID:", info.messageId);
    return true;
  } catch (err) {
    console.log("Error sending email:", err.message);
    return false;
  }
};

module.exports = SendEmail;
module.exports.transporter = transporter;
