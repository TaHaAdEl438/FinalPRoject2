import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import ApiError from '../utils/apiError.js';
import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto'; // لإنتاج رمز عشوائي
import sendEmail from '../utils/sendEmail.js'; // لإرسال البريد الإلكتروني

// Generate token
const createToken = (payload) =>
  jwt.sign({ userId: payload }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_SECRET_TIME,
  });

// @desc  Signup
// @route POST /api/v1/auth/signup
// @access Public
export const signup = asyncHandler(async (req, res, next) => {
  const { name, email, password } = req.body;

  // التحقق من إدخال جميع البيانات المطلوبة
  if (!name || !email || !password) {
    return next(new ApiError('Please provide name, email, and password.', 400));
  }

  // التحقق مما إذا كان البريد الإلكتروني مستخدمًا مسبقًا
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new ApiError('E-mail already in use', 400));
  }

  // 1- إنشاء المستخدم
  const user = await User.create({ name, email, password }).catch(err => {
    return next(new ApiError(err.message, 500));
  });

  // 2- إنشاء التوكن
  const token = createToken(user._id);

  res.status(201).json({ data: user, token });
});

// @desc  Login
// @route POST /api/v1/auth/login
// @access Public
export const login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new ApiError('Please provide email and password.', 400));
  }

  // البحث عن المستخدم مع تضمين كلمة المرور
  const user = await User.findOne({ email }).select('password');
  if (!user) {
    return next(new ApiError('Incorrect email or password!', 401));
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return next(new ApiError('Incorrect email or password', 401));
  }

  const token = createToken(user._id);

  res.status(200).json({
    message: "Login successful",
    data: {
      _id: user._id,
      name: user.name,
      email: user.email,
    },
    token,
  });
});

// @desc  Protect routes
// @access Private
export const protect = asyncHandler(async (req, res, next) => {
  // 1) check if token exist , if exist get it
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1]; // تم تصحيح الخطأ هنا (إضافة مسافة في split)
  }
  if (!token) {
    return next(
      new ApiError(
        'You are not login , Please login to get access to this route',
        401
      )
    );
  }

  // 2) Verify token (no change happen ,expire token)
  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.userId);
  if (!currentUser) {
    return next(
      new ApiError('The user belonging to this token no longer exists.', 401)
    );
  }

  // 4) Grant access to the route
  req.user = currentUser;
  next();
});

// @desc  Forget Password
// @route POST /api/v1/auth/forgetPassword
// @access Public
export const forgetPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new ApiError('Please provide your email.', 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new ApiError('No user found with this email.', 404));
  }

  // إنشاء رمز إعادة تعيين كلمة المرور
  const resetToken = crypto.randomBytes(32).toString('hex');
  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 دقائق

  await user.save({ validateBeforeSave: false });

  // إرسال البريد الإلكتروني
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

    return next(new ApiError('There was an error sending the email. Try again later!', 500));
  }
});

// @desc  Reset Password
// @route PATCH /api/v1/auth/resetPassword/:token
// @access Public
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