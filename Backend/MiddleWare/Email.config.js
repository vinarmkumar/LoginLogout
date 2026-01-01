const SibApiV3Sdk = require("sib-api-v3-sdk");
require('dotenv').config();

// Configure Brevo API client
const client = SibApiV3Sdk.ApiClient.instance;
client.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;

// Create transactional emails API instance
const transactionalEmailsApi = new SibApiV3Sdk.TransactionalEmailsApi();

// Verify API connection
if (!process.env.BREVO_API_KEY) {
  console.error("❌ BREVO_API_KEY is missing in .env file");
} else if (!process.env.BREVO_SENDER_EMAIL) {
  console.error("❌ BREVO_SENDER_EMAIL is missing in .env file");
} else {
  console.log("✅ Brevo API configured successfully");
  console.log("   API Key: " + process.env.BREVO_API_KEY.slice(0, 5) + "...");
  console.log("   Sender Email: " + process.env.BREVO_SENDER_EMAIL);
}

module.exports = { transactionalEmailsApi, SibApiV3Sdk };
