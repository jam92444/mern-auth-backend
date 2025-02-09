import jwt from "jsonwebtoken";

//we are adding the next parameter to run this function after completing this function next will execute the controller function.
const userAuth = async (req, res, next) => {
  const { token } = req.cookies; //from cookie it will try to find the token

  if (!token) {
    return res.json({ success: false, message: "Not authorized Login again." });
  }

  //if token available
  try {

    //to verify we need to decode the token to do we use jwt
    const tokenDecode = jwt.verify(token,process.env.JWT_SECRET);

    //fron tokenDecode we need to find the userId
    if(tokenDecode.id){
        req.body.userId = tokenDecode.id;

    }else{
        return res.json({ success: false, message: "Not authorized Login again." });
    }

    next();
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export default userAuth;
