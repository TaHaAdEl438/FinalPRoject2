// routes/categoryRoute.js
import express from 'express';
import { uploadPhoto,resizePhotoProject,updateOne } from '../controller/userController.js';
import authController from '../controller/authController.js';

const router = express.Router();

router.route('/upd-image')
  .patch(authController.protect,uploadPhoto,resizePhotoProject,updateOne);

export default router;