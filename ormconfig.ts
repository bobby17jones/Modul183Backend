import {DataSource} from "typeorm";
import dotenv from "dotenv";

dotenv.config();

const connectDB = new DataSource({
    "type": "mysql",
    "host": "localhost",
    "port": 3306,
    "username": "root",
    "password": "root",
    "database": "node_auth",
    "entities": [
        "src/entity/*.ts"
    ],
    "logging": false,
    "synchronize": true
});

connectDB
    .initialize()
    .then(() => {
        console.log(`Data Source has been initialized`);
    })
    .catch((err) => {
        console.error(`Data Source initialization error`, err);
    })

export default connectDB;