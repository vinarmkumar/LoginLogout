import { useNavigate } from 'react-router-dom'
import validator from 'validator'
import { useState, useEffect } from 'react'
import backgroundImage from '../../Images/signinbackground.jpg'

export default function Login() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [resetCode, setResetCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [mode, setMode] = useState('login') // 'login', 'verify', 'forgot-password', 'reset-password', 'account-locked'
  const [resendCooldown, setResendCooldown] = useState(0)
  const [accountLockTimer, setAccountLockTimer] = useState(0)
  const [attemptsRemaining, setAttemptsRemaining] = useState(3)

  // Resend cooldown timer
  useEffect(() => {
    let interval
    if (resendCooldown > 0) {
      interval = setInterval(() => {
        setResendCooldown(prev => prev - 1)
      }, 1000)
    }
    return () => clearInterval(interval)
  }, [resendCooldown])

  // Account lock timer
  useEffect(() => {
    let interval
    if (accountLockTimer > 0) {
      interval = setInterval(() => {
        setAccountLockTimer(prev => prev - 1)
      }, 1000)
    }
    return () => clearInterval(interval)
  }, [accountLockTimer])

  const handlelogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    if (!validator.isEmail(email)) {
      setError('Please enter a valid email address')
      setLoading(false)
      return
    }

    if (!password) {
      setError('Password is required')
      setLoading(false)
      return
    }

    try {
      const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      })

      const data = await response.json()

      if (response.ok) {
        alert('Login Successful - Email is verified')
        navigate('/')
      } else {
        // Check if account is locked
        if (data.accountLocked) {
          setMode('account-locked')
          setAccountLockTimer(data.timeRemaining)
          setError(data.message)
        } else if (data.message && data.message.includes('verify')) {
          // If email not verified, show verification mode
          setMode('verify')
          setError(data.message)
        } else {
          // Invalid credentials
          setError(data.message || 'Invalid credentials')
          setAttemptsRemaining(data.attemptsRemaining || 3)
        }
      }
    } catch (err) {
      setError('Error connecting to server')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    if (!verificationCode) {
      setError('Verification code is required')
      setLoading(false)
      return
    }

    try {
      const response = await fetch('http://localhost:3000/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, verificationCode })
      })

      const data = await response.json()

      if (response.ok) {
        alert('Email verified successfully! Now logging you in...')
        
        // Auto login after verification
        const loginResponse = await fetch('http://localhost:3000/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email, password })
        })

        if (loginResponse.ok) {
          navigate('/')
        }
      } else {
        setError(data.message || 'Verification failed')
      }
    } catch (err) {
      setError('Error connecting to server')
    } finally {
      setLoading(false)
    }
  }

  const handleForgotPassword = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    if (!validator.isEmail(email)) {
      setError('Please enter a valid email address')
      setLoading(false)
      return
    }

    try {
      const response = await fetch('http://localhost:3000/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      })

      const data = await response.json()

      if (response.ok) {
        alert('Password reset code sent to your email')
        setMode('reset-password')
        setError('')
        setResendCooldown(30)
      } else {
        setError(data.message || 'Error sending reset code')
      }
    } catch (err) {
      setError('Error connecting to server')
    } finally {
      setLoading(false)
    }
  }

  const handleResetPassword = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    if (!resetCode) {
      setError('Reset code is required')
      setLoading(false)
      return
    }

    if (!newPassword) {
      setError('New password is required')
      setLoading(false)
      return
    }

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      setLoading(false)
      return
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      setLoading(false)
      return
    }

    try {
      const response = await fetch('http://localhost:3000/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, resetCode, newPassword })
      })

      const data = await response.json()

      if (response.ok) {
        alert('Password reset successfully! You can now login with your new password.')
        setMode('login')
        setEmail('')
        setPassword('')
        setResetCode('')
        setNewPassword('')
        setConfirmPassword('')
        setError('')
      } else {
        setError(data.message || 'Password reset failed')
      }
    } catch (err) {
      setError('Error connecting to server')
    } finally {
      setLoading(false)
    }
  }

  const handleResendResetCode = async () => {
    setLoading(true)

    try {
      const response = await fetch('http://localhost:3000/resend-reset-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      })

      const data = await response.json()

      if (response.ok) {
        alert('New reset code sent to your email')
        setResetCode('')
        setResendCooldown(30)
      } else {
        setError(data.message || 'Error resending code')
      }
    } catch (err) {
      setError('Error connecting to server')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div 
      className="flex items-center justify-center min-h-screen bg-cover bg-center"
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      <div className="w-[420px] bg-white rounded-2xl shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="h-24 flex items-center justify-center bg-amber-200">
          <h1 className="text-4xl font-bold text-gray-900">
            {mode === 'login' ? 'Login' : mode === 'verify' ? 'Verify Email' : mode === 'forgot-password' ? 'Forgot Password' : mode === 'account-locked' ? 'Account Locked' : 'Reset Password'}
          </h1>
        </div>

        {/* Error */}
        {error && (
          <p className="text-red-500 text-center mt-4 px-6">
            {error}
          </p>
        )}

        {/* Forms Container */}
        {mode === 'login' && (
        <form onSubmit={handlelogin} className="px-8 py-8 space-y-6">

          {/* Email */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Email
            </label>
            <input
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={`w-full px-4 py-2 rounded-md border 
                focus:outline-none focus:ring-2
                ${error ? 'border-red-400 focus:ring-red-400' : 'border-gray-300 focus:ring-amber-500'}`}
            />
          </div>

          {/* Password */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Password
            </label>
            <input
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={`w-full px-4 py-2 rounded-md border 
                focus:outline-none focus:ring-2
                ${error ? 'border-red-400 focus:ring-red-400' : 'border-gray-300 focus:ring-amber-500'}`}
            />
          </div>

          {/* Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 font-bold text-white rounded-md bg-amber-800 hover:bg-amber-900 transition disabled:bg-gray-400"
          >
            {loading ? 'Signing In...' : 'Sign In'}
          </button>

          {/* Forgot Password Link */}
          <p className="text-center text-sm">
            <span
              className="text-amber-700 font-semibold cursor-pointer hover:underline"
              onClick={() => {
                setMode('forgot-password')
                setError('')
                setEmail('')
              }}
            >
              Forgot Password?
            </span>
          </p>

          {/* Footer */}
          <p className="text-sm text-center text-gray-600">
            Don't have an account?
            <span
              className="ml-1 text-amber-700 font-semibold cursor-pointer hover:underline"
              onClick={() => navigate('/register')}
            >
              Sign Up
            </span>
          </p>

        </form>
        )}

        {mode === 'verify' && (
        <form onSubmit={handleVerify} className="px-8 py-8 space-y-6">

          {/* Email Display */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Email
            </label>
            <input
              type="email"
              value={email}
              disabled
              className="w-full px-4 py-2 rounded-md border border-gray-300 bg-gray-100 cursor-not-allowed"
            />
          </div>

          {/* Verification Code */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Verification Code
            </label>
            <input
              type="text"
              placeholder="Enter 6-digit code from email"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              className="w-full px-4 py-2 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-green-600"
            />
          </div>

          {/* Verify Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 font-bold text-white rounded-md bg-green-600 hover:bg-green-700 transition disabled:bg-gray-400"
          >
            {loading ? 'Verifying...' : 'Verify Email & Login'}
          </button>

          {/* Back Button */}
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setVerificationCode('')
              setError('')
            }}
            className="w-full py-2 font-semibold text-gray-600 rounded-md border border-gray-300 hover:bg-gray-50 transition"
          >
            Back to Login
          </button>

        </form>
        )}

        {mode === 'forgot-password' && (
        <form onSubmit={handleForgotPassword} className="px-8 py-8 space-y-6">

          {/* Email */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Email
            </label>
            <input
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <p className="text-sm text-gray-600 text-center">
            Enter your email address to receive a password reset code.
          </p>

          {/* Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 font-bold text-white rounded-md bg-blue-600 hover:bg-blue-700 transition disabled:bg-gray-400"
          >
            {loading ? 'Sending Code...' : 'Send Reset Code'}
          </button>

          {/* Back Button */}
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setEmail('')
              setError('')
            }}
            className="w-full py-2 font-semibold text-gray-600 rounded-md border border-gray-300 hover:bg-gray-50 transition"
          >
            Back to Login
          </button>

        </form>
        )}

        {mode === 'reset-password' && (
        <form onSubmit={handleResetPassword} className="px-8 py-8 space-y-6">

          {/* Email Display */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Email
            </label>
            <input
              type="email"
              value={email}
              disabled
              className="w-full px-4 py-2 rounded-md border border-gray-300 bg-gray-100 cursor-not-allowed"
            />
          </div>

          {/* Reset Code */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Reset Code
            </label>
            <input
              type="text"
              placeholder="Enter 6-digit code from email"
              value={resetCode}
              onChange={(e) => setResetCode(e.target.value)}
              maxLength="6"
              className="w-full px-4 py-2 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {/* New Password */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              New Password
            </label>
            <input
              type="password"
              placeholder="At least 8 characters"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-4 py-2 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {/* Confirm Password */}
          <div>
            <label className="block mb-1 font-semibold text-gray-700">
              Confirm Password
            </label>
            <input
              type="password"
              placeholder="Confirm your password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-4 py-2 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {/* Reset Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 font-bold text-white rounded-md bg-blue-600 hover:bg-blue-700 transition disabled:bg-gray-400"
          >
            {loading ? 'Resetting Password...' : 'Reset Password'}
          </button>

          {/* Resend Code */}
          <p className="text-center text-sm">
            Didn't receive code?{' '}
            <span
              onClick={handleResendResetCode}
              className={`font-semibold cursor-pointer ${
                resendCooldown > 0 ? 'text-gray-400 cursor-not-allowed' : 'text-blue-700 hover:underline'
              }`}
            >
              {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend Code'}
            </span>
          </p>

          {/* Back Button */}
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setEmail('')
              setResetCode('')
              setNewPassword('')
              setConfirmPassword('')
              setError('')
            }}
            className="w-full py-2 font-semibold text-gray-600 rounded-md border border-gray-300 hover:bg-gray-50 transition"
          >
            Back to Login
          </button>

        </form>
        )}

        {mode === 'account-locked' && (
        <div className="px-8 py-8 space-y-6">
          
          <div className="text-center">
            <div className="text-6xl mb-4">🔒</div>
            <p className="text-lg font-semibold text-red-600 mb-4">
              Account Temporarily Locked
            </p>
            <p className="text-sm text-gray-600 mb-4">
              Due to 3 failed login attempts, your account is locked for security reasons.
            </p>
          </div>

          {/* Lock Timer */}
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <p className="text-center text-sm text-red-700 font-semibold">
              Account will unlock in:
            </p>
            <p className="text-center text-4xl font-bold text-red-600 mt-2">
              {Math.floor(accountLockTimer / 60)}:{(accountLockTimer % 60).toString().padStart(2, '0')}
            </p>
          </div>

          <div className="text-center">
            <p className="text-sm text-gray-600 mb-4">
              If you remember your password, you can reset it to unlock your account immediately.
            </p>
          </div>

          {/* Reset Password Button */}
          <button
            type="button"
            onClick={() => {
              setMode('forgot-password')
              setError('')
              setEmail('')
            }}
            className="w-full py-2 font-bold text-white rounded-md bg-blue-600 hover:bg-blue-700 transition"
          >
            Reset Password & Unlock Account
          </button>

          {/* Back Button */}
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setEmail('')
              setPassword('')
              setError('')
              setAccountLockTimer(0)
            }}
            className="w-full py-2 font-semibold text-gray-600 rounded-md border border-gray-300 hover:bg-gray-50 transition"
          >
            Back
          </button>

        </div>
        )}
      </div>
    </div>
  )
}
