// routes/categoryRoute.js
import express from 'express';
import { getCategories, createCategory } from '../controller/categoryController.js';
import authController from '../controller/authController.js';

const router = express.Router();

router.route('/')
  .get(getCategories)
  .post(authController.protect, createCategory);

export default router;