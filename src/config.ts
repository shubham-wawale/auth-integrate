import dotenv from 'dotenv'
dotenv.config();

export const config = {
    POSTGRES: process.env.POSTGRES || "",
    JWT_SECRET: process.env.JWT_SECRET || "9194928317"
}



