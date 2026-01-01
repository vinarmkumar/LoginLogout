const { Verification_Email_Template, Password_Reset_Email_Template } = require('../Libs/EmailTemplate.js');
const { transactionalEmailsApi, SibApiV3Sdk } = require('./Email.config.js');
require('dotenv').config();

const SendVerificationCode = async (email, verificationCode) => {
  try {
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = "Verify your Email ✔";
    sendSmtpEmail.htmlContent = Verification_Email_Template.replace("{verificationCode}", verificationCode);
    sendSmtpEmail.sender = {
      name: process.env.BREVO_SENDER_NAME || "LoginLogout",
      email: process.env.BREVO_SENDER_EMAIL,
    };
    sendSmtpEmail.to = [{ email: email }];

    const response = await transactionalEmailsApi.sendTransacEmail(sendSmtpEmail);
    console.log("Verification email sent successfully to:", email, "Message ID:", response.messageId);
    return true;
  } catch (err) {
    console.log("Error sending verification email:", err.message);
    return false;
  }
};

const SendPasswordResetCode = async (email, resetCode) => {
  try {
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = "Reset Your Password ✔";
    sendSmtpEmail.htmlContent = Password_Reset_Email_Template.replace("{resetCode}", resetCode);
    sendSmtpEmail.sender = {
      name: process.env.BREVO_SENDER_NAME || "LoginLogout",
      email: process.env.BREVO_SENDER_EMAIL,
    };
    sendSmtpEmail.to = [{ email: email }];

    const response = await transactionalEmailsApi.sendTransacEmail(sendSmtpEmail);
    console.log("Password reset email sent successfully to:", email, "Message ID:", response.messageId);
    return true;
  } catch (err) {
    console.log("Error sending password reset email:", err.message);
    return false;
  }
};

module.exports = { SendVerificationCode, SendPasswordResetCode };