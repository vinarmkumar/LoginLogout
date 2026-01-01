const { SendVerificationCode } = require('./MiddleWare/Email');

// Test email sending
async function testEmail() {
  console.log("🧪 Starting email test...\n");
  
  try {
    const testEmail = "test@example.com"; // Use a real test email
    const testCode = "123456";
    
    console.log("Sending test verification email to:", testEmail);
    const result = await SendVerificationCode(testEmail, testCode);
    
    if (result) {
      console.log("\n✅ Email test PASSED - Check your inbox!");
    } else {
      console.log("\n❌ Email test FAILED - Check console errors above");
    }
  } catch (err) {
    console.error("Test error:", err);
  }
}

testEmail();
