// controller/authController.js
import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import ApiError from '../utils/apiError.js';
import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

//import twilio from 'twilio';

//const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

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

  const emailVerificationToken = Math.floor(100000 + Math.random() * 900000).toString();
  const emailVerifiedExpired = Date.now() + 2 * 60 * 1000;

  const user = await User.create({
    name,
    email,
    password,
    emailVerificationToken,
    emailVerifiedExpired
  }).catch((err) => {
    return next(new ApiError(err.message, 500));
  });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
    },
});

  const mailOptions = {
    from:"Sign-Language-Translation-Robot",
    to: user.email,
    subject: "Verify Your Account",
    html: `
        <!DOCTYPE html>
  <html lang="en">
  <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Account</title>
  <style>
  body {
    font-family: 'Arial', sans-serif;
    background-color: #f0f8ff;
    margin: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }

  .container {
    background-color: #ffffff;
    padding: 30px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
    text-align: center;
    max-width: 400px;
    width: 100%;
  }

  h1 {
    color: #4A90E2;
    font-size: 26px;
    margin-bottom: 20px;
  }

  .otp {
    font-size: 28px;
    letter-spacing: 5px;
    margin: 20px 0;
    padding: 10px;
    border: 2px solid #4A90E2;
    border-radius: 5px;
    display: inline-block;
    background-color: #f1f8ff;
    color: #4A90E2;
  }

  .message {
    font-size: 16px;
    color: #333;
    margin-top: 10px;
  }

  .footer {
    font-size: 14px;
    color: #888;
    margin-top: 20px;
  }

  .copyright {
    font-size: 12px;
    color: #999;
    margin-top: 10px;
  }
  </style>
  </head>
  <body>

  <div class="container">
  <h1>Verify Your Account</h1>

  <p>Hi ${user.name},</p>

  <p>Thank you for registering with Sign Language Translation.</p>

  <p>Here is your OTP code:</p>

  <div class="otp">${emailVerificationToken}</div>

  <p class="message">Please enter this code to verify your account.</p>

  <p class="footer">This OTP is valid for 2 minutes.</p>

  <p class="copyright">&copy; 2025 Sign Language Translation. All rights reserved.</p>
  </div>

  </body>
  </html>

        `,
  }

  try {
   await transporter.sendMail(mailOptions);
   return res.status(201).json({
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

  //const user = await User.findOne({ emailVerificationToken: token });

  const user = await User.findOne({
    emailVerificationToken: token,
    emailVerifiedExpired: { $gt: Date.now() },
});


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

  const user = email ? await User.findOne({ email:email,emailVerified:true }) : await User.findOne({ phone });
  if (!user) {
    return next(new ApiError('No user found with this email or phone.', 404));
  }

  const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  user.passwordResetVerified = false,

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

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD,
      },
  });
  const mailOptions = {
    from: "Sign-Language-Translation-Robot",
    to: user.email,
    subject: "Reset Password",
    html: `
       <html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reset Password</title>
<style>
    body {
        font-family: 'Arial', sans-serif;
        background-color: #f0f8ff;
        margin: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
    }

    .container {
        background-color: #ffffff;
        padding: 30px;
        border-radius: 10px;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
        text-align: center;
        max-width: 400px;
        width: 100%;
    }

    h1 {
        color: #4A90E2;
        font-size: 26px;
        margin-bottom: 20px;
    }

    .otp {
        font-size: 28px;
        letter-spacing: 5px;
        margin: 20px 0;
        padding: 10px;
        border: 2px solid #4A90E2;
        border-radius: 5px;
        display: inline-block;
        background-color: #f1f8ff;
        color: #4A90E2;
    }

    .message {
        font-size: 16px;
        color: #333;
        margin-top: 10px;
    }
    
    .footer {
        font-size: 14px;
        color: #888;
        margin-top: 20px;
    }

    .copyright {
        font-size: 12px;
        color: #999;
        margin-top: 10px;
    }
</style>
</head>
<body>

<div class="container">
    <h1>Reset Your Password</h1>
    
    <p>Hi ${user.name},</p>
    
    <p>We received a request to reset the password on your Sign Language Translation account.</p>
    
    <p>Here is your OTP code:</p>
    
    <div class="otp">${resetToken}</div>
    
    <p class="message">Please enter this code to reset your password. The code is valid for 10 minutes.</p>
    
    <p class="footer">If you did not request a password reset, please ignore this email.</p>
    
    <p class="copyright">&copy; 2025 Sign Language Translation. All rights reserved.</p>
</div>

</body>
</html>
        `,
}
    try {
      await transporter.sendMail(mailOptions);

      return res.status(200).json({
        status: 'success',
        message: 'Token sent to email!',
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      user.passwordResetVerified = undefined;
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
  user.passwordResetVerified = true;

  await user.save();

  const newToken = createToken(user._id);

  res.status(200).json({
    status: 'success',
    token: newToken,
  });
});

export const sendAgain = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new ApiError('E-mail already in not Exist, please signup again', 400));
  }
  const emailVerificationToken = Math.floor(100000 + Math.random() * 900000).toString();
  const emailVerifiedExpired = Date.now() + 2 * 60 * 1000;
  user.emailVerificationToken = emailVerificationToken
  user.emailVerifiedExpired = emailVerifiedExpired
  await user.save();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
    },
});

  const mailOptions = {
    from:"Sign-Language-Translation-Robot",
    to: user.email,
    subject: "Verify Your Account",
    html: `
        <!DOCTYPE html>
  <html lang="en">
  <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Account</title>
  <style>
  body {
    font-family: 'Arial', sans-serif;
    background-color: #f0f8ff;
    margin: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }

  .container {
    background-color: #ffffff;
    padding: 30px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
    text-align: center;
    max-width: 400px;
    width: 100%;
  }

  h1 {
    color: #4A90E2;
    font-size: 26px;
    margin-bottom: 20px;
  }

  .otp {
    font-size: 28px;
    letter-spacing: 5px;
    margin: 20px 0;
    padding: 10px;
    border: 2px solid #4A90E2;
    border-radius: 5px;
    display: inline-block;
    background-color: #f1f8ff;
    color: #4A90E2;
  }

  .message {
    font-size: 16px;
    color: #333;
    margin-top: 10px;
  }

  .footer {
    font-size: 14px;
    color: #888;
    margin-top: 20px;
  }

  .copyright {
    font-size: 12px;
    color: #999;
    margin-top: 10px;
  }
  </style>
  </head>
  <body>

  <div class="container">
  <h1>Verify Your Account</h1>

  <p>Hi ${user.name},</p>

  <p>Thank you for registering with Sign Language Translation.</p>

  <p>Here is your OTP code:</p>

  <div class="otp">${emailVerificationToken}</div>

  <p class="message">Please enter this code to verify your account.</p>

  <p class="footer">This OTP is valid for 2 minutes.</p>

  <p class="copyright">&copy; 2025 Sign Language Translation. All rights reserved.</p>
  </div>

  </body>
  </html>

        `,
  }

  try {
      //await sendOtp(user.phoneNumber, resetCode, "verification");//send otp via whatsapp
       await transporter.sendMail(mailOptions);
       return res.status(201).json({
        status: 'success',
        message: 'Please verify your email to log in.',
        data: user,
      });
  } catch (err) {
    await User.deleteOne({ _id: user._id });
    return next(new ApiError('Error sending verification email. Try again later.', 500));
  }
});

export default {
  signup,
  login,
  protect,
  forgetPassword,
  resetPassword,
  verifyEmail,
  sendAgain
};