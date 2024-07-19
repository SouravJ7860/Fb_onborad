const { User } = require('./model');
const checkUserExists = async (req, res, next) => {
 
  const { email, phone } = req.body;
  try {
    if (email , phone ) {
      const user = await User.findOne({ email });
      if (user) { 
        return res.status(400).json({ message: 'User with this email or phone already exists' });
      }
    }
    if (phone) {
      const user = await User.findOne({ phone });
      if (user) {
        return res.status(400).json({ message: 'User with this phone already exists' });
      }
    }
    next();
  } catch (error) {
    console.error('Error in checkUserExists:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = {checkUserExists};
