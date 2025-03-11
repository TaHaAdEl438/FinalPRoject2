// controller/authController.js
import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import ApiError from '../utils/apiError.js';
import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import sendEmail from '../utils/sendEmail.js';
import twilio from 'twilio';

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const createToken = (payload) =>
  jwt.sign({ userId: payload }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_SECRET_TIME,
  });

export const signup = asyncHandler(async (req, res, next) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return next(new ApiError('Please provide name, email, and password.', 400));
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new ApiError('E-mail already in use', 400));
  }

  const emailVerificationToken = crypto.randomBytes(32).toString('hex');
  const user = await User.create({
    name,
    email,
    password,
    emailVerificationToken,
  }).catch((err) => {
    return next(new ApiError(err.message, 500));
  });

  const verificationURL = `${req.protocol}://${req.get('host')}/api/v1/auth/verifyEmail/${emailVerificationToken}`;
  const message = `Please verify your email by clicking this link: ${verificationURL}.\nThis link is valid for 24 hours.`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Email Verification (Valid for 24 hours)',
      message,
    });

    res.status(201).json({
      status: 'success',
      message: 'User created. Please verify your email to log in.',
      data: user,
    });
  } catch (err) {
    await User.deleteOne({ _id: user._id });
    return next(new ApiError('Error sending verification email. Try again later.', 500));
  }
});

export const verifyEmail = asyncHandler(async (req, res, next) => {
  const { token } = req.params;

  const user = await User.findOne({ emailVerificationToken: token });
  if (!user) {
    return next(new ApiError('Invalid or expired verification token.', 400));
  }

  user.emailVerified = true;
  user.emailVerificationToken = undefined;
  await user.save();

  const tokenJwt = createToken(user._id);

  res.status(200).json({
    status: 'success',
    message: 'Email verified successfully!',
    token: tokenJwt,
  });
});

export const login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new ApiError('Please provide email and password.', 400));
  }

  const user = await User.findOne({ email }).select('password emailVerified');
  if (!user || !user.emailVerified) {
    return next(new ApiError('Please verify your email before logging in.', 401));
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return next(new ApiError('Incorrect email or password', 401));
  }

  const token = createToken(user._id);

  res.status(200).json({
    message: 'Login successful',
    data: {
      _id: user._id,
      name: user.name,
      email: user.email,
    },
    token,
  });
});

export const protect = asyncHandler(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    return next(
      new ApiError(
        'You are not logged in. Please log in to get access to this route.',
        401
      )
    );
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
  const currentUser = await User.findById(decoded.userId);
  if (!currentUser) {
    return next(
      new ApiError('The user belonging to this token no longer exists.', 401)
    );
  }

  req.user = currentUser;
  next();
});

export const forgetPassword = asyncHandler(async (req, res, next) => {
  const { email, phone, resetVia } = req.body;

  if (!email && !phone) {
    return next(new ApiError('Please provide your email or phone number.', 400));
  }

  const user = email ? await User.findOne({ email }) : await User.findOne({ phone });
  if (!user) {
    return next(new ApiError('No user found with this email or phone.', 404));
  }

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  await user.save({ validateBeforeSave: false });

  if (resetVia === 'phone' && user.phone) {
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.passwordResetToken = crypto.createHash('sha256').update(resetCode).digest('hex');

    try {
      await twilioClient.messages.create({
        body: `Your password reset code is: ${resetCode}. Valid for 10 minutes.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: user.phone,
      });

      await user.save({ validateBeforeSave: false });
      res.status(200).json({
        status: 'success',
        message: 'Reset code sent to phone!',
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      return next(new ApiError('Error sending SMS. Try again later.', 500));
    }
  } else {
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/auth/resetPassword/${resetToken}`;
    const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message,
      });

      res.status(200).json({
        status: 'success',
        message: 'Token sent to email!',
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      return next(new ApiError('Error sending email. Try again later.', 500));
    }
  }
});

export const resetPassword = asyncHandler(async (req, res, next) => {
  const { token } = req.params;
  const { password, passwordConfirm } = req.body;

  if (!password || !passwordConfirm) {
    return next(new ApiError('Please provide password and passwordConfirm.', 400));
  }

  if (password !== passwordConfirm) {
    return next(new ApiError('Passwords do not match.', 400));
  }

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ApiError('Token is invalid or has expired.', 400));
  }

  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  const newToken = createToken(user._id);

  res.status(200).json({
    status: 'success',
    token: newToken,
  });
});

export default {
  signup,
  login,
  protect,
  forgetPassword,
  resetPassword,
  verifyEmail,
};