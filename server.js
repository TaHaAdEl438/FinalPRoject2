// server.js
import express from "express";
import morgan from "morgan";
import ApiError from "./utils/apiError.js";
import globalError from "./middlewares/errorMiddleware.js";
import cors from "cors";
import categoryRoute from "./routes/categoryRoute.js";
import authRoute from "./routes/authRoute.js";
import userRoute from './routes/userRoute.js'
import dotenv from 'dotenv';
import dbConnection from "./config/database.js";

const app = express();

app.use(express.json());

dotenv.config({ path: './config.env' });

app.use(
  cors({
    origin: "http://localhost:8000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

if (!process.env.MONGO_URI) {
  console.error("Error: MONGO_URI is not defined in config.env");
  process.exit(1);
}

console.log("MONGO_URI:", process.env.MONGO_URI);

dbConnection();

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
  console.log(`Mode: ${process.env.NODE_ENV}`);
}

app.use("/api/v1/categories", categoryRoute);
app.use("/api/v1/auth", authRoute);
app.use("/api/v1/user", userRoute);

app.all("*", (req, res, next) => {
  next(new ApiError(`Can't find this route: ${req.originalUrl}`, 400));
});

app.use(globalError);

const PORT = process.env.PORT || 8000;
const server = app.listen(PORT, () => {
  console.log(`App running on port ${PORT}`);
});

process.on("unhandledRejection", (err) => {
  console.error(`Unhandled Rejection: ${err.name} | ${err.message}`);
  server.close(() => {
    console.error("Shutting down...");
    process.exit(1);
  });
});