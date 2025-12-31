const { Verification_Email_Template, Password_Reset_Email_Template } = require('../Libs/EmailTemplate.js');
const { transporter } = require('./Email.config.js');

const SendVerificationCode = async (email,verificationCode) => {
     try{
       const response = await transporter.sendMail({
          from: '"VerifiedAuthority" <princekumarjmp1729@gmail.com>',
          to: email,
          subject: "Verify your Email ✔",
          text: "Verify your Email", // Plain-text version of the message
          html: Verification_Email_Template.replace("{verificationCode}", verificationCode), // HTML version of the message
        });
    console.log("Email sent successfully:", response.messageId);
       return true;
     }
     catch(err){
         console.log("Error sending email:", err.message);
     }
}

const SendPasswordResetCode = async (email, resetCode) => {
     try{
       const response = await transporter.sendMail({
          from: '"VerifiedAuthority" <princekumarjmp1729@gmail.com>',
          to: email,
          subject: "Reset Your Password ✔",
          text: "Reset Your Password", // Plain-text version of the message
          html: Password_Reset_Email_Template.replace("{resetCode}", resetCode), // HTML version of the message
        });
    console.log("Email sent successfully:", response.messageId);
       return true;
     }
     catch(err){
         console.log("Error sending email:", err.message);
     }
}

module.exports = { SendVerificationCode, SendPasswordResetCode };