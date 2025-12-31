const jwt = require('jsonwebtoken');
const User = require('../Models/User');
require('dotenv').config();

const userAuth = async(req, res, next)=>{
    try{
        if(!req.cookies.token){
            return res.status(401).json({message: "No token provided"});
        }
        
        const {token} = req.cookies;
        if(!token){
            return res.status(401).json({message: "No token found"});
        }
        
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const {_id} = payload;
        
        if(!_id){
            return res.status(401).json({message: "Invalid token payload"});
        }
        
        const result = await User.findById(_id);
        if(!result){
            return res.status(404).json({message: "User not found"});
        }
        
        req.userId = _id;
        next();
    }
    catch(err){
        console.error(err);
        res.status(401).json({message: "Invalid or expired token"});
    }
}

module.exports = userAuth;