import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodeMailer.js";

export const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: "Missing Details" });
  }

  try {
    //this line check whether user is already in the db or usermodel necause before hashin the password we need  to check its already existing or not .
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res.json({ success: false, message: "User Already exist!!" });
    }

    //if user not exist we move onto hashing and store in our usermodel
    const hashedPassword = await bcrypt.hash(password, 10);

    //now we have created user useing the user model. now we need to store them
    const user = new userModel({ name, email, password: hashedPassword });

    await user.save();

    //now we need to create a authentication token and we will send the token using the cookies.

    //generating token and whenever ne wuser added jwt will add _id in the user object and we are using this to stoer the id in the token

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    }); // expiresin tells for how many days this token will be valid in this case its 7 days.

    //now we need to send the  res using cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //sending  welcome mail
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to mysite",
      text: `Hey ${name}, Thank you for registering into our site with email: ${email}. We happy to hear from you if anything we can do.`,
    };

    //sending the mail
    await transporter.sendMail(mailOptions);

    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ success: false, message: "Email and password required" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "Invalid Email" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ success: false, message: "Invalid Password" });
    }

    //generating token and whenever ne wuser added jwt will add _id in the user object and we are using this to stoer the id in the token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    }); // expiresin tells for how many days this token will be valid in this case its 7 days.

    //now we need to send the  res using cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    return res.json({ success: true, message: "Logged Out" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

//Send Verification OTP to the User 's Email
export const sendVerifyOtp = async (req, res) => {
  try {
    //here we are getting  the userid and otp but the user only send the opt.For that we have set the token in cookie. using the cookie we get the user and then we get the user id we do all these using middleware
    const { userId } = req.body;

    const user = await userModel.findById(userId);

    //checking if the user already verified their email
    if (user.isAccountVerified) {
      return res.json({ success: true, message: "Account Already verified" });
    }

    //if user is not verified by their email we have to generate OTP to make them verify

    //OTP Number generating it will generate 6 digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    //now we have to store the otp in the usermodel where we have created verify otp.
    user.verifyOtp = otp;

    //now we have to set expiry time for the otp.
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    //now we need to send otp to user email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification One Time Password (OTP)",
      text: `Your OTP(One Time Password) is ${otp}. Verify your account using this otp. This OTP will be expired with in 24 hrs.`,
    };

    //sending mail
    await transporter.sendMail(mailOptions);

    //sending response
    res.json({ success: true, message: "Verification OTP Send on Email." });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

//Verifying Email using the Otp sended on the mail.
export const verifyEmail = async (req, res) => {
  //here we are getting  the userid and otp but the user only send the opt.For that we have set the token in cookie. using the cookie we get the user and then we get the user id we do all these using middleware.

  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing Details" });
  }
  try {
    //find the user from the userid
    const user = await userModel.findById(userId);

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // checking the otp provided is not same
    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    //if otp matches checking whether the otp is expired.
    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired." });
    }

    // if otp is not expired we will set account as verified.
    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;

    await user.save();

    return res.json({ success: true, message: "Email verified Successfully." });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

//Check user is authenticated
export const isAuthenticated = async (req, res) => {
  try {
    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};


//send password reset otp
export const sendResetOtp = async (req,res) => {
  const {email} = req.body;

  if(!email){
    return res.json({success:false,message:"Email is required"})
  }
  try {
    const user = await userModel.findOne({email});

    if(!user){
      return res.json({success:false,message:"User not found!."})

    }

    //OTP Number generating it will generate 6 digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    //now we have to store the otp in the usermodel where we have created verify otp.
    user.resetOtp = otp;

    //now we have to set expiry time for the otp.
    user.resetOtpExpireAt = Date.now() + 15* 60 * 1000;

    await user.save();

    //now we need to send otp to user email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset One Time Password (OTP)",
      text: `Your OTP(One Time Password) for resetting the password is ${otp}. Verify your account using this otp. Use this OTP to proceed resetting the password. NOTE: OTP will be expired in 15 min.`,
    };

    //sending mail
    await transporter.sendMail(mailOptions);

    return res.json({success:true,message:"OTP send to your email."})


  } catch (error) {
    res.json({ success: false, message: error.message });
  }
  
}

//Verifying the OTP and resetting the Password.
export const resetPassword = async (req,res) => {

  const {email,otp,newPassword} = req.body;

  if(!email || !newPassword || !otp){
    return res.json({success:false,message:"Email,OTP and Password are required."});
  }

  try {

    const user = await userModel.findOne({email});

    if(!user){
      return res.json({success:false,message:"User not found"});
    }

    if(user.resetOtp === "" || user.resetOtp !== otp){
      return res.json({success:false,message:"Invalid OTP"})
    }

    if(user.resetOtpExpireAt < Date.now()){
      return res.json({success:false,message:"OTP expired"});
    }

    const hashedPassword = await bcrypt.hash(newPassword,10);

    user.password = hashedPassword;
    user.resetOtp = '';
    user.resetOtpExpireAt = 0;

    await user.save();

    res.json({success:true,message:"Password has been reset successfully."})
    
  } catch (error) {
    res.json({ success: false, message: error.message });
    
  }
  
}