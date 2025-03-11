// routes/authRoute.js
import express from 'express';
import { signupValidator, loginValidator } from '../utils/validator/authValidator.js';
import authController from '../controller/authController.js';

const router = express.Router();

router.post('/signup', signupValidator, authController.signup);
router.post('/login', loginValidator, authController.login);
router.post('/forgetPassword', authController.forgetPassword);
router.patch('/resetPassword/:token', authController.resetPassword);
router.get('/verifyEmail/:token', authController.verifyEmail);

export default router;