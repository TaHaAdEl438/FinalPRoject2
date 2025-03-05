// categoryRoute.js
import express from 'express';
import { getCategories, createCategory } from '../controller/categoryController.js';
import { protect } from '../controller/authController.js'; // تم تصحيح الاستيراد

const router = express.Router();

router.route('/')
  .get(getCategories)
  .post(protect, createCategory); // تم استخدام protect هنا

export default router;