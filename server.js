import express from 'express'
import cors from 'cors';
import 'dotenv/config'
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRoutes.js';
import userRouter from './routes/userRoutes.js';


const app = express();
const port = process.env.PORT || 4000
connectDB();

const allowedOrigins = ['https://authmyj.vercel.app']

app.use(express.json());    
app.use(cookieParser());
app.use(cors({origin:allowedOrigins,credentials:true})); //by giving the credentials true we can pass the cookie

//api endpointes 
app.get('/',(req,res)=>{
    res.send("API working")
})
app.use('/api/auth',authRouter)
app.use('/api/user',userRouter)

app.listen(port,()=>{
    console.log(`server started on port : ${port}`);
     
})
