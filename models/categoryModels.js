import mongoose from 'mongoose';

// 1- create Schema
const categorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'category required'],
      unique: [true, 'category must be unique'],
      minLength: [3, 'Too short category name'],
      maxLength: [32, 'Too long category name'],
    },
    slug: {
      type: String,
      lowercase: true,
    },
    image: String,
  },
  { timestamps: true }
);

// 2- create model
const categoryModel = mongoose.model('Category', categorySchema);

export default categoryModel;
