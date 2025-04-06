import asyncHandler from 'express-async-handler';
import appError from '../utils/apiError.js';
import User from '../models/userModel.js';
import cloudinary from "../utils/cloud.js"
import multer from "multer"

const multerStorage = multer.memoryStorage()

const multerFilter = (req, file, cb) => {
    if (file.mimetype.startsWith("image")) {
        cb(null, true)
    } else {
        cb(new appError('not an image ! please upload only images..', 400), false)
    }
}

const upload = multer({
    storage: multerStorage,
    fileFilter: multerFilter
})

export const uploadPhoto = upload.single('profileImg')

export const resizePhotoProject = asyncHandler(async (req, res, next) => {

    if (!req.file) return next()

    const fileName = `${req.file.originalname}`
    const filePath = `SignPR/Users`

    const result = await uploadToCloudinary(req.file.buffer, fileName, filePath)
    req.body.profileImg = result.secure_url

    next()
})

const uploadToCloudinary = (buffer, filename ='', folderPath = '',options={}) => {
   
    return new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        {
          folder: folderPath,
          public_id: filename,
          resource_type: 'auto',
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      ).end(buffer); // No need to await upload_stream, it's not a promise
    });
  };

export const updateOne = asyncHandler(async (req, res, next) => {

    const doc = await User.findByIdAndUpdate(req.user.id, req.body, { new: true }) //new is true => to return new doc after update

    if (!doc) {
        return next(new appError(`Can't find User on this id`, 404));
    }

    // doc.save()

    res.status(201).json({
        status: "success",
        data: {
            data: doc
        }
    })
})

export default {
    updateOne,
    resizePhotoProject,
    uploadPhoto
  };