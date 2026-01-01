import { useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import backgroundImage from '../../Images/signinbackground.jpg'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  const rules = [
    { regex: /.{8,}/, message: 'Password must be at least 8 characters long.' },
    { regex: /[a-z]/, message: 'Password must contain at least one lowercase letter.' },
    { regex: /[A-Z]/, message: 'Password must contain at least one uppercase letter.' },
    { regex: /\d/, message: 'Password must contain at least one number.' },
    { regex: /[!@#$%^&*(),.?":{}|<>]/, message: 'Password must contain at least one special character.' },
  ];

  const errors = rules
    .filter(rule => !rule.regex.test(password))
    .map(rule => rule.message);

  return errors;
};

export default function Signup() {
  const navigate = useNavigate();

  const [step, setStep] = useState(1); // 1: Register, 2: Verify Email
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [timeLeft, setTimeLeft] = useState(300); // 5 minutes in seconds
  const [resendLoading, setResendLoading] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0); // 30 second cooldown

  // Cleanup when component unmounts or user leaves
  useEffect(() => {
    const handleBeforeUnload = async () => {
      if (step === 2 && email) {
        // User is leaving during verification step - cleanup
        try {
          await fetch(`${API_URL}/cleanup-unverified`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email })
          });
        } catch (err) {
          console.error('Cleanup error:', err);
        }
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [step, email]);

  // Timer for verification code expiry
  useEffect(() => {
    let interval;
    if (step === 2 && timeLeft > 0) {
      interval = setInterval(() => {
        setTimeLeft(prev => {
          if (prev <= 1) {
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => clearInterval(interval);
  }, [step, timeLeft]);

  // Resend cooldown timer (30 seconds)
  useEffect(() => {
    let interval;
    if (step === 2 && resendCooldown > 0) {
      interval = setInterval(() => {
        setResendCooldown(prev => prev - 1);
      }, 1000);
    }

    return () => clearInterval(interval);
  }, [step, resendCooldown]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  const handleSignUp = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (!validateEmail(email)) {
      setError('Invalid email format');
      setLoading(false);
      return;
    }

    const passwordErrors = validatePassword(password);
    if (passwordErrors.length > 0) {
      setError(passwordErrors[0]); // show first error
      setLoading(false);
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name, email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.message || 'Registration failed');
        setLoading(false);
        return;
      }

      // Move to verification step
      setStep(2);
      setTimeLeft(300); // Reset timer to 5 minutes
      setResendCooldown(0); // Can resend immediately after signup
      setLoading(false);

    } catch (err) {
      console.error('Error:', err);
      setError('Server error. Please make sure the backend is running on http://localhost:3000');
      setLoading(false);
    }
  };

  const handleVerifyEmail = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (!verificationCode) {
      setError('Verification code is required');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/verify-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, verificationCode }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.message || 'Verification failed');
        setLoading(false);
        return;
      }

      alert('Email verified successfully! Redirecting to login...');
      navigate('/login');

    } catch (err) {
      console.error('Error:', err);
      setError('Server error. Please make sure the backend is running.');
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setError('');
    setResendLoading(true);

    try {
      const response = await fetch(`${API_URL}/resend-verification-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.message || 'Failed to resend code');
        setResendLoading(false);
        return;
      }

      // Reset timer and UI
      setTimeLeft(300); // Reset to 5 minutes
      setVerificationCode('');
      setResendCooldown(30); // Start 30 second cooldown
      alert('New verification code sent to your email!');
      setResendLoading(false);

    } catch (err) {
      console.error('Error:', err);
      setError('Server error. Please try again.');
      setResendLoading(false);
    }
  };

  return (
    <div 
      className="flex items-center justify-center min-h-screen bg-cover bg-center"
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      <div className="w-[420px] bg-white rounded-2xl shadow-2xl">

        {/* Header */}
        <div className="flex items-center justify-center h-24 bg-amber-200 rounded-t-2xl">
          <h1 className="text-4xl font-bold text-gray-900">
            {step === 1 ? 'Create Account' : 'Verify Email'}
          </h1>
        </div>

        {error && (
          <div className="px-8 py-4">
            <p className="text-red-500 text-center">{error}</p>
          </div>
        )}

        {/* Registration Form */}
        {step === 1 ? (
        <form onSubmit={handleSignUp} className="px-8 py-2 space-y-6">

          <div>
            <label className="block mb-2 font-semibold text-gray-800">
              Full Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter your name"
              className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-amber-500"
              required
            />
          </div>

          <div>
            <label className="block mb-2 font-semibold text-gray-800">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-amber-500"
              required
            />
          </div>

          <div>
            <label className="block mb-2 font-semibold text-gray-800">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a password"
              className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-amber-500"
              required
            />
          </div>

          <div>
            <label className="block mb-2 font-semibold text-gray-800">
              Confirm Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your password"
              className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-amber-500"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 font-bold text-white bg-amber-800 rounded-md hover:bg-amber-900 transition"
          >
            {loading ? 'Signing Up...' : 'Sign Up'}
          </button>

          <p className="text-sm text-center text-gray-600">
            Already have an account?
            <span
              className="ml-1 font-semibold text-amber-700 cursor-pointer hover:underline"
              onClick={() => navigate('/login')}
            >
              Log In
            </span>
          </p>
        </form>
        ) : (
        // Verification Form
        <form onSubmit={handleVerifyEmail} className="px-8 py-8 space-y-6">

          <div>
            <label className="block mb-2 font-semibold text-gray-800">
              Email
            </label>
            <input
              type="email"
              value={email}
              disabled
              className="w-full px-4 py-2 border rounded-md bg-gray-100 cursor-not-allowed"
            />
          </div>

          <div>
            <label className="block mb-2 font-semibold text-gray-800">
              Verification Code
            </label>
            <p className="text-sm text-gray-600 mb-2">Check your email for the 6-digit code</p>
            <p className={`text-sm font-semibold mb-2 ${timeLeft > 60 ? 'text-blue-600' : 'text-red-600'}`}>
              Time remaining: {formatTime(timeLeft)}
            </p>
            <input
              type="text"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              placeholder="Enter 6-digit code"
              className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-green-500"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 font-bold text-white bg-green-600 rounded-md hover:bg-green-700 transition disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify Email & Complete Sign Up'}
          </button>

          {/* Resend Code Text Link */}
          <div className="flex justify-center items-center gap-2">
            <p className="text-sm text-gray-600">Didn't receive code?</p>
            {resendCooldown > 0 ? (
              <span className="text-sm font-semibold text-amber-600">
                Resend in {resendCooldown}s
              </span>
            ) : (
              <button
                type="button"
                onClick={handleResendCode}
                disabled={resendLoading}
                className="text-sm font-semibold text-blue-600 hover:text-blue-800 hover:underline cursor-pointer transition disabled:opacity-50"
              >
                {resendLoading ? 'Sending...' : 'Resend Code'}
              </button>
            )}
          </div>

          <button
            type="button"
            onClick={async () => {
              // Cleanup before going back
              try {
                await fetch(`${API_URL}/cleanup-unverified`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  credentials: 'include',
                  body: JSON.stringify({ email })
                });
              } catch (err) {
                console.error('Cleanup error:', err);
              }
              setStep(1)
              setVerificationCode('')
              setError('')
              setTimeLeft(300)
              setResendCooldown(0)
            }}
            className="w-full py-2 font-semibold text-gray-600 border rounded-md hover:bg-gray-50 transition"
          >
            Back
          </button>
        </form>
        )}
      </div>
    </div>

  );
}
