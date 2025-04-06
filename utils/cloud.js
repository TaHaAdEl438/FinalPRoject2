import c from "cloudinary"
const cloudinary = c.v2

import dotenv from 'dotenv';
dotenv.config({ path: './config.env' });

cloudinary.config({ 
        cloud_name:process.env.CLOUDINARY_USER_NAME, 
        api_key:process.env.CLOUDINARY_API_KEY, 
        api_secret:process.env.CLOUDINARY_API_SECRET
      });
      
export default cloudinary