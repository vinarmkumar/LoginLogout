const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const {Schema} = mongoose;

const userSchema = new Schema({
    name: {
      type: String,
      required: [true, 'Name is required'],
      minlength: [3, 'Name must be at least 3 characters'],
      maxlength: [50, 'Name must be at most 50 characters'],
      trim: true
    },
  
      email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: validator.isEmail,
        message: 'Please enter a valid email address'
      }
    },
   
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      maxlength: [128, 'Password is too long'],
      select: false
    },
     role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
  verificationCode: {
      type: String,
      default: null
    },
    
    isVerified: {
      type: Boolean,
      default: false
    },
    
    verificationCodeExpiry: {
      type: Date,
      default: null
    },

    // Password reset fields
    resetPasswordCode: {
      type: String,
      default: null
    },

    resetPasswordCodeExpiry: {
      type: Date,
      default: null
    },

    // Account lockout fields
    failedLoginAttempts: {
      type: Number,
      default: 0
    },

    loginLockedUntil: {
      type: Date,
      default: null
    }
   
},
{
    timestamps: true 
  }
);

// Add schema methods BEFORE creating the model
userSchema.methods.getJwt = function(){
  const token = jwt.sign({_id: this._id, emailId: this.email}, process.env.JWT_SECRET, {expiresIn: '1h'});
  return token;
}

userSchema.methods.comparePassword = async function(Userpassword){
  const ans =  await bcrypt.compare(Userpassword, this.password);
  return ans;
}

const User = mongoose.model("user", userSchema);




module.exports = User;