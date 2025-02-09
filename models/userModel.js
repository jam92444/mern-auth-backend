import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true,
    },

    // store the otp when the otp send to the mail id 
    verifyOtp:{
        type:String,
        default:'',
    },

    //expiry time for otp
    verifyOtpExpireAt:{
        type:Number,
        default:0,
    },
    // check whether the user is varified by default user is not verified user will be verified when otp is matched
    isAccountVerified:{
        type:Boolean,
        default:false,
    },
    resetOtp:{
        type:String,
        default:'',
    },
    resetOtpExpireAt:{
        type:Number,
        default:0,
    },
})

const userModel = mongoose.models.user || mongoose.model('user',userSchema);

export default userModel;