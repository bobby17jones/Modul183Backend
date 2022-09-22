require('dotenv').config()

import express, {Request, Response} from 'express';
import connectDB from '../ormconfig';
import { routes } from './routes';
import cors from 'cors';
import cookieParser from 'cookie-parser';

connectDB

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:8081'],
    credentials: true
}));

routes(app);

app.listen(8000, () => {
    console.log('listening to port 8000')
});