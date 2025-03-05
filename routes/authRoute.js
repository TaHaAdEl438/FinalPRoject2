import express from 'express';
import { signupValidator, loginValidator } from '../utils/validator/authValidator.js';
import { signup, login, forgetPassword, resetPassword } from '../controller/authController.js';

const router = express.Router();

router.post('/signup', signupValidator, signup);
router.post('/login', loginValidator, login);
router.post('/forgetPassword', forgetPassword);
router.patch('/resetPassword/:token', resetPassword);

export default router;