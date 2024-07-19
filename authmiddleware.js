const jwt = require('jsonwebtoken');
const { User } = require('./model');
const JWT_SECRET = '7988';


const authToken = async(req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });
  
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Bearer token missing' });
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      if(user){
        req.user = user;
      }
      if (!user) return res.status(403).json({ message: 'User not found' });
  
      req.user = user;
      next();
    } catch (err) {
      return res.status(403).json({ message: 'Please authenticate.' });
    }
  };

  module.exports = authToken;