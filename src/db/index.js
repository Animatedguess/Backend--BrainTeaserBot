import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";
import dotenv from 'dotenv';
import app from "../app.js";

dotenv.config({
    path: "./.env"
});

const connectDB = async ()=>{
    try {
        const databaseInstant = await mongoose.connect(`${process.env.DATABASE_URL}/${DB_NAME}`);
        console.log("database is connacted "+databaseInstant)
        app.on("error",(error)=>{
            console.log(`ERROR: ${error}`)
            throw error;
        })
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
}

export default connectDB;