const mongoose = require('mongoose');
const validator = require('validator');

const { Schema } = mongoose;

const tempUserSchema = new Schema(
  {
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
      maxlength: [128, 'Password is too long']
    },

    verificationCode: {
      type: String,
      required: true
    },

    verificationCodeExpiry: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + 5 * 60 * 1000) // 5 minutes from now
    }
  },
  {
    timestamps: true
  }
);

// Auto-delete expired verification codes after 5 minutes
tempUserSchema.index(
  { verificationCodeExpiry: 1 },
  { expireAfterSeconds: 0 }
);

const TempUser = mongoose.model('tempuser', tempUserSchema);

module.exports = TempUser;
