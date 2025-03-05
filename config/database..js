import mongoose from 'mongoose';

const dbConnection = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI); // استخدم process.env
    console.log(`✅ Database connected: ${conn.connection.host}`);
  } catch (err) {
    console.error(`❌ Database connection failed: ${err.message}`);
    process.exit(1);
  }
};

export default dbConnection;