const express = require('express');
const main = require('./database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();
const User = require('./Models/User');
const TempUser = require('./Models/TempUser');
const cookieParser = require('cookie-parser');
const userAuth = require('./MiddleWare/userAuth');
const { SendVerificationCode, SendPasswordResetCode } = require('./MiddleWare/Email');
require('dotenv').config();

// ==================== SECURITY MIDDLEWARE ====================
// Helmet for HTTP headers security
app.use(helmet());

// Body parser middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: true }));
// Use a cookie secret when available so signed cookies work correctly.
// Falls back to a development-only secret if not provided.
const cookieSecret = process.env.COOKIE_SECRET || 'dev-cookie-secret-please-change';
app.use(cookieParser(cookieSecret));

// CORS Configuration
const cors = require('cors');
const corsOptions = {
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 3600
};
app.use(cors(corsOptions));

// Root route to verify backend is running
app.get('/', (req, res) => {
    res.json({ message: 'Backend is running!' });
});

// ==================== RATE LIMITING ====================
// General API rate limit
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Auth endpoints rate limit (stricter)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again later.',
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
});

// Email sending rate limit
const emailLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 3, // limit each IP to 3 requests per minute
    message: 'Too many email requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', generalLimiter);

// ==================== ENVIRONMENT VALIDATION ====================
const requiredEnvVars = [
    'DB_CONNECT_KEY',
    'JWT_SECRET',
    'BREVO_API_KEY',
    'BREVO_SENDER_EMAIL'
];

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`❌ Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

console.log(`✅ All required environment variables are set`);
console.log(`🔒 Running in ${process.env.NODE_ENV || 'development'} mode`);

// ==================== UTILITY FUNCTIONS ====================
// Standardized API response
const sendResponse = (res, statusCode, message, data = null) => {
    const response = { message };
    if (data) response.data = data;
    return res.status(statusCode).json(response);
};

// Input sanitization
const sanitizeEmail = (email) => {
    return email.toLowerCase().trim();
};

// ==================== ROUTES ====================

// Get user info (protected route)
app.get('/user', userAuth, async(req, res)=>{
    try{
        const userId = req.userId;
        const result = await User.findById(userId).select('-password');
        
        if(!result){
            return sendResponse(res, 404, "User not found");
        }

        sendResponse(res, 200, "User retrieved successfully", result);
    }
    catch(err){
        console.error('Error fetching user:', err);
        sendResponse(res, 500, "Error fetching user");
    }
});

// Get all users (admin only) - protected route
app.get('/info', userAuth, async (req, res) => {
    try {
        const allUsers = await User.find().select('-password');
        sendResponse(res, 200, "Users retrieved successfully", allUsers);
    } catch (err) {
        console.error('Error fetching users:', err);
        sendResponse(res, 500, "Error fetching users");
    }
});

// Register endpoint
app.post('/register', authLimiter, emailLimiter, async(req, res)=>{
    try{
        const { name, email, password } = req.body;
        
        // Validate input
        if(!name || !email || !password){
            return sendResponse(res, 400, "Name, email, and password are required");
        }
        
        // Sanitize inputs
        const sanitizedEmail = sanitizeEmail(email);
        const sanitizedName = name.trim();
        
        // Validate name
        if(sanitizedName.length < 3 || sanitizedName.length > 50){
            return sendResponse(res, 400, "Name must be between 3 and 50 characters");
        }
        
        // Validate email
        if(!validator.isEmail(sanitizedEmail)){
            return sendResponse(res, 400, "Invalid email format");
        }
        
        // Validate password strength
        if(password.length < 8){
            return sendResponse(res, 400, "Password must be at least 8 characters");
        }
        
        if(!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password)){
            return sendResponse(res, 400, "Password must contain uppercase, lowercase, and numbers");
        }
        
        // Check if user already exists in permanent database
        const existingUser = await User.findOne({email: sanitizedEmail});
        if(existingUser){
            return sendResponse(res, 409, "Email already registered");
        }

        // Check if temporary user already exists
        const existingTempUser = await TempUser.findOne({email: sanitizedEmail});
        if(existingTempUser){
            // Delete old temporary user and create new one
            await TempUser.deleteOne({email: sanitizedEmail});
        }
        
        // Hash the password with bcrypt
        const hashedPassword = await bcrypt.hash(password, 12);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationCodeExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now

        // Store user data temporarily
        const tempUser = await TempUser.create({
            name: sanitizedName,
            email: sanitizedEmail,
            password: hashedPassword,
            verificationCode,
            verificationCodeExpiry
        });
        
        // Set cookie to store temporary user data
        res.cookie('tempUser', JSON.stringify({
            tempUserId: tempUser._id,
            email: sanitizedEmail,
            expiresAt: verificationCodeExpiry.getTime()
        }), {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 5 * 60 * 1000, // 5 minutes
            signed: true
        });
        
        // Send verification email
        console.log("🚀 Calling SendVerificationCode function...");
        const emailResult = await SendVerificationCode(sanitizedEmail, verificationCode);
        console.log("📬 Email result:", emailResult ? "✅ Sent" : "❌ Failed");
        
        if(!emailResult){
            await TempUser.deleteOne({email: sanitizedEmail});
            return sendResponse(res, 500, "Failed to send verification email. Please try again.");
        }
        
        sendResponse(res, 201, "Registration started. Verification code sent to your email. You have 5 minutes to verify.", {
            email: sanitizedEmail,
            expiresIn: 300 // 5 minutes in seconds
        });
    }
    catch(err){
        console.error("❌ Register endpoint error:", err && err.stack ? err.stack : err);
        // Keep the client-facing message generic but log full stack for debugging.
        sendResponse(res, 500, "Error registering user");
    }
});

// Login endpoint
app.post('/login', authLimiter, async(req, res)=>{
    try{
        const {email, password} = req.body;
        
        // Validate input
        if(!email || !password){
            return sendResponse(res, 400, "Email and password are required");
        }
        
        const sanitizedEmail = sanitizeEmail(email);
        
        if(!validator.isEmail(sanitizedEmail)){
            return sendResponse(res, 400, "Invalid email format");
        }
        
        // Find user and select password field
        const user = await User.findOne({email: sanitizedEmail}).select('+password');
        
        if(!user){
            // Avoid revealing if user exists
            return sendResponse(res, 401, "Invalid email or password");
        }

        // Check if account is locked due to failed login attempts
        if(user.loginLockedUntil && user.loginLockedUntil > new Date()){
            const timeRemaining = Math.ceil((user.loginLockedUntil - new Date()) / 1000);
            return sendResponse(res, 429, `Account locked. Try again in ${timeRemaining} seconds or reset your password.`, {
                accountLocked: true,
                timeRemaining: timeRemaining,
                suggestPasswordReset: true
            });
        }

        // Reset failed attempts if lockout period has expired
        if(user.loginLockedUntil && user.loginLockedUntil <= new Date()){
            user.failedLoginAttempts = 0;
            user.loginLockedUntil = null;
        }
        
        // Check if email is verified
        if(!user.isVerified){
            return sendResponse(res, 403, "Please verify your email first. Check your inbox for verification code.");
        }
        
        const isPasswordValid = await user.comparePassword(password);
        if(!isPasswordValid){
            // Increment failed login attempts
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

            // Lock account after 3 failed attempts
            if(user.failedLoginAttempts >= 3){
                user.loginLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
                await user.save();
                return sendResponse(res, 429, `Account locked due to failed login attempts. Please reset your password to continue.`, {
                    accountLocked: true,
                    timeRemaining: 900,
                    suggestPasswordReset: true
                });
            }

            // Save updated failed attempts
            await user.save();
            const remainingAttempts = 3 - user.failedLoginAttempts;
            return sendResponse(res, 401, `Invalid credentials. ${remainingAttempts} attempt(s) remaining.`, {
                attemptsRemaining: remainingAttempts
            });
        }

        // Reset failed attempts on successful login
        user.failedLoginAttempts = 0;
        user.loginLockedUntil = null;
        await user.save();
        
        // Generate token with shorter expiry for production
        const token = jwt.sign(
            { _id: user._id, emailId: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRY || '1h' }
        );
        
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 1000, // 1 hour
            signed: true
        });
        
        sendResponse(res, 200, "Login successful", {
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isVerified: user.isVerified
            }
        });
    }
    catch(err){
        console.error('Login error:', err);
        sendResponse(res, 500, "Login error");
    }   
});

app.post('/logout', userAuth, async (req, res)=>{
    try{
        res.clearCookie('token');
        res.status(200).json({message: 'Logout successful'});
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: 'Logout error'});
    }
});

app.delete('/user', userAuth, async (req, res)=>{
    try{
        const userId = req.userId;
        
        const result = await User.findByIdAndDelete(userId);
        if(!result){
            return res.status(404).json({message: "User not found"});
        }
        
        res.clearCookie('token');
        res.status(200).json({message: 'Account deleted successfully'});
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: 'Error deleting account'});
    }
});

app.delete('/admin/user/:id', userAuth, async (req, res)=>{
    try{
        const {id} = req.params;
        
        const result = await User.findByIdAndDelete(id);
        if(!result){
            return res.status(404).json({message: "User not found"});
        }
        
        res.status(200).json({message: 'User deleted successfully'});
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: 'Error deleting user'});
    }
});

app.post('/verify-email', async(req, res)=>{
    try{
        const {email, verificationCode} = req.body;
        
        if(!email || !verificationCode){
            return res.status(400).json({message: "Email and verification code required"});
        }
        
        // Find the temporary user
        const tempUser = await TempUser.findOne({email: email});
        if(!tempUser){
            return res.status(404).json({message: "Registration not found. Please register again"});
        }
        
        // Check if verification code has expired
        if(new Date() > tempUser.verificationCodeExpiry){
            await TempUser.deleteOne({email: email});
            return res.status(401).json({message: "Verification code expired. Please register again"});
        }
        
        // Verify the code
        if(tempUser.verificationCode !== verificationCode){
            return res.status(400).json({message: "Invalid verification code"});
        }
        
        // Create permanent user from temporary user
        const newUser = await User.create({
            name: tempUser.name,
            email: tempUser.email,
            password: tempUser.password,
            isVerified: true,
            verificationCode: null
        });
        
        // Delete temporary user
        await TempUser.deleteOne({email: email});
        
        // Clear the tempUser cookie
        res.clearCookie('tempUser');
        
        res.status(200).json({
            message: "Email verified successfully. Account created. You can now login.",
            user: {id: newUser._id, name: newUser.name, email: newUser.email}
        });
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: "Error verifying email"});
    }
});

app.post('/resend-verification-code', async(req, res)=>{
    try{
        const {email} = req.body;
        
        if(!email){
            return res.status(400).json({message: "Email is required"});
        }
        
        // Find temporary user
        const tempUser = await TempUser.findOne({email: email});
        if(!tempUser){
            return res.status(404).json({message: "Registration not found. Please register again"});
        }
        
        // Generate new verification code
        const newVerificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const newExpiryTime = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now
        
        // Update temporary user with new code and expiry
        tempUser.verificationCode = newVerificationCode;
        tempUser.verificationCodeExpiry = newExpiryTime;
        await tempUser.save();
        
        // Update cookie expiry time
        res.cookie('tempUser', JSON.stringify({
            tempUserId: tempUser._id,
            email: email,
            expiresAt: newExpiryTime.getTime()
        }), {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 5 * 60 * 1000 // 5 minutes
        });
        
        // Send new verification email
        await SendVerificationCode(email, newVerificationCode);
        
        res.status(200).json({
            message: "New verification code sent to your email. You have 5 minutes to verify.",
            expiresIn: 300 // 5 minutes in seconds
        });
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: "Error resending verification code"});
    }
});

app.post('/cleanup-unverified', async(req, res)=>{
    try{
        const {email} = req.body;
        
        if(!email){
            return res.status(400).json({message: "Email is required"});
        }
        
        // Delete temporary user if user leaves without verifying
        const result = await TempUser.deleteOne({email: email});
        
        // Clear the tempUser cookie
        res.clearCookie('tempUser');
        
        res.status(200).json({message: "Unverified registration cleaned up"});
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: "Error cleaning up"});
    }
});

// Forgot Password - Send reset code to email
app.post('/forgot-password', async(req, res)=>{
    try{
        const {email} = req.body;
        
        if(!email){
            return res.status(400).json({message: "Email is required"});
        }

        // Find user by email
        const user = await User.findOne({email: email});
        if(!user){
            return res.status(404).json({message: "User not found with this email"});
        }

        // Generate reset code (6 digits)
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        const resetCodeExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        // Update user with reset code and expiry
        user.resetPasswordCode = resetCode;
        user.resetPasswordCodeExpiry = resetCodeExpiry;
        await user.save();

        // Send reset code email
        await SendPasswordResetCode(email, resetCode);

        res.status(200).json({
            message: "Password reset code sent to your email. Valid for 5 minutes.",
            expiresIn: 300 // 5 minutes in seconds
        });
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: "Error sending reset code"});
    }
});

// Verify reset code and reset password
app.post('/reset-password', async(req, res)=>{
    try{
        const {email, resetCode, newPassword} = req.body;
        
        if(!email || !resetCode || !newPassword){
            return res.status(400).json({message: "Email, reset code, and new password are required"});
        }

        // Validate password
        if(newPassword.length < 8){
            return res.status(400).json({message: "Password must be at least 8 characters"});
        }

        // Find user by email
        const user = await User.findOne({email: email}).select('+password');
        if(!user){
            return res.status(404).json({message: "User not found"});
        }

        // Check if reset code is valid and not expired
        if(user.resetPasswordCode !== resetCode || !user.resetPasswordCodeExpiry || user.resetPasswordCodeExpiry < new Date()){
            return res.status(400).json({message: "Invalid or expired reset code"});
        }

        // Check if new password is same as old password
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if(isSamePassword){
            return res.status(400).json({message: "You can't use the same password. Try another password"});
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update user password
        user.password = hashedPassword;
        user.resetPasswordCode = null;
        user.resetPasswordCodeExpiry = null;
        await user.save();

        res.status(200).json({message: "Password reset successful. You can now login with your new password."});
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: "Error resetting password"});
    }
});

// Resend reset password code
app.post('/resend-reset-code', async(req, res)=>{
    try{
        const {email} = req.body;
        
        if(!email){
            return res.status(400).json({message: "Email is required"});
        }

        // Find user by email
        const user = await User.findOne({email: email});
        if(!user){
            return res.status(404).json({message: "User not found with this email"});
        }

        // Generate new reset code
        const newResetCode = Math.floor(100000 + Math.random() * 900000).toString();
        const newResetCodeExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        // Update user with new reset code
        user.resetPasswordCode = newResetCode;
        user.resetPasswordCodeExpiry = newResetCodeExpiry;
        await user.save();

        // Send reset code email
        await SendPasswordResetCode(email, newResetCode);

        res.status(200).json({
            message: "New reset code sent to your email. Valid for 5 minutes.",
            expiresIn: 300
        });
    }
    catch(err){
        console.error(err);
        res.status(500).json({message: "Error resending reset code"});
    }
});

main()
.then(async() => {
    console.log("Database connected");
    app.listen(process.env.PORT || 3000, () => {
  console.log(`Server is running on port ${process.env.PORT || 3000}`);
});

})
.catch((err) => {
    console.log(err);
}); 









