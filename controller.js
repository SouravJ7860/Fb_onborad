// const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const mongoose = require('mongoose');
const path = require('path');
const upload = require('./config/multerConfig');
const { User, OTP, FriendRequest, Post, LikeDislike, Comment , Block} = require('./model');
const { sendGmail } = require('./mailer');
const { signupSchema, verifySignupOTPSchema, loginSchema, verifyLoginOTPSchema, resetPasswordSchema, forgotPasswordSchema, updateProfileSchema, resendOTPSchema } = require('./validation');


// Add your secret key for JWT
const JWT_SECRET = '7988';

// Function to send SMS (placeholder)
const sendSMS = async (phone, message) => {
  console.log(`Sending SMS to ${phone}: ${message}`);
  // Implement actual SMS sending logic here, e.g., using a third-party service like Twilio
};

// Signup Controller
exports.signup = async (req, res) => {
  const { error } = signupSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email, phone, countryCode, password } = req.body;

  try {
    // Check if email already exists in User
    let user = null;
    if (email) {
      user = await User.findOne({ email });
      if (user && user.verified) {
        return res.status(400).json({ message: 'Email already in use.' });
      }
    }

    // Check if phone already exists in User
    if (phone) {
      user = await User.findOne({ phone });
      if (user && user.verified) {
        return res.status(400).json({ message: 'Phone already in use.' });
      }
    }

    // Hash password if user does not exist or is not verified
    const hashedPassword = user ? user.password : await bcrypt.hash(password, 10);

    // Handle Email Signup
    if (email) {
      const otp = '123456'; // Use a static OTP for email verification
      const otpExpires = Date.now() + 300000; // 5 minutes from now

      // Create or update user with verified set to false
      user = await User.findOneAndUpdate(
        { email },
        { email, password: hashedPassword, verified: false, countryCode },
        { upsert: true, new: true, strict: false }
      );

      // Upsert OTP
      await OTP.findOneAndUpdate(
        { email },
        { email, otp, otpExpires },
        { upsert: true, new: true }
      );

      // Send OTP to user's email
      sendGmail(email, 'Signup OTP', `Your OTP is ${otp}`); 
      return res.status(200).json({ message: 'OTP sent to email.' });
    }

    // Handle Phone Signup
    else if (phone) {
      const otp = '123456'; // Use a static OTP for phone verification
      const otpExpires = Date.now() + 300000; // 5 minutes from now

      // Create or update user with verified set to false
      user = await User.findOneAndUpdate(
        { phone },
        { phone, password: hashedPassword, verified: false, countryCode },
        { upsert: true, new: true, strict: false }
      );

      // Upsert OTP
      await OTP.findOneAndUpdate(
        { phone },
        { phone, otp, otpExpires },
        { upsert: true, new: true }
      );

      return res.status(200).json({ message: 'OTP sent to Phone.' });
    } else {
      return res.status(400).json({ message: 'Email or phone is required.' });
    }
  } catch (error) {
    console.error('Error in signup:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


exports.verifySignupOTP = async (req, res) => {
  const { error } = verifySignupOTPSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email, phone, otp } = req.body;

  try {
    let otpEntry;
    if (phone) {
      otpEntry = await OTP.findOne({ phone, otp });
    } else if (email) {
      otpEntry = await OTP.findOne({ email, otp });
    } else {
      return res.status(400).json({ message: 'Email or phone is required.' });
    }

    if (!otpEntry || otpEntry.otpExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }

    // Delete OTP entry and update user verification status
    if (phone) {
      await OTP.deleteOne({ phone, otp });
      await User.updateOne({ phone }, { verified: true });
    } else if (email) {
      await OTP.deleteOne({ email, otp });
      await User.updateOne({ email }, { verified: true });
    }

    return res.status(200).json({ message: 'Verified User Created successfully.' });
  } catch (error) {
    console.error('Error in verifySignupOTP:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// Login Controller
exports.login = async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email, phone, countryCode, password } = req.body;
  try {
    let user;
    if (email) {
      user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'User with this email does not exist' });
      }
    } else if (phone) {
      user = await User.findOne({ phone, countryCode });
      if (!user) {
        return res.status(400).json({ message: 'User with this phone and country code does not exist' });
      }
    } else {
      return res.status(400).json({ message: 'Email or phone is required' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    if (phone) {
      // Generate OTP
      const otp = 123456;
      const otpExpires = Date.now() + 300000; // 5 minutes from now

      // Upsert OTP
      await OTP.findOneAndUpdate(
        { phone },
        { phone, otp, otpExpires },
        { upsert: true, new: true }
      );

      // Send OTP to user's phone
      await sendSMS(phone, `Your login OTP is ${otp}`);

      return res.status(200).json({ message: `OTP sent to phone ${phone}.` });
    } else {
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

      return res.status(200).json({
        token,
        message: 'User logged in successfully',
        user: {
          id: user._id,
          email: user.email,
          phone: user.phone,
          countryCode: user.countryCode,
        },
      });
    }
  } catch (error) {
    console.error('Error in login:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


exports.verifyLoginOTP = async (req, res) => {
  const { error } = verifyLoginOTPSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { phone, otp } = req.body;

  try {
    const otpEntry = await OTP.findOne({ phone, otp });
    if (!otpEntry || otpEntry.otpExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }

    // Delete OTP entry after successful verification
    await OTP.deleteOne({ phone, otp });

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(400).json({ message: 'User not found.' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({
      token,
      message: 'User logged in successfully',
      user: {
        id: user._id,
        email: user.email,
        phone: user.phone,
        countryCode: user.countryCode,
      },
    });
  } catch (error) {
    console.error('Error in verifyLoginOTP:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// Get Profile Controller
exports.getProfile = async (req, res) => {
  return res.status(200).json({ Userdata: req.user });
};

// Update Profile Controller 
exports.updateProfile = async (req, res) => {
  try {
    const { error } = updateProfileSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const user = req.user; // Assuming req.user contains the authenticated user's data
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const updatedFields = req.body;

    // Update user profile fields
    Object.assign(user, updatedFields);

    // Save updated user profile in the database
    await user.save();

    // Respond with updated user details
    res.json({
      message: 'Profile updated successfully',
      userData: user
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
};


exports.resendOTP = async (req, res) => {
  const { error } = resendOTPSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { email } = req.body;
  try {

    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.verified) {
      return res.status(400).json({ message: 'Email is already verified.' });
    }

    // Generate OTP
    // const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otp = 123456;
    const otpExpires = Date.now() + 300000; // 5 minutes from now

    // Update or insert OTP
    await OTP.findOneAndUpdate(
      { email },
      { email, otp, otpExpires },
      { upsert: true, new: true }
    );

    // Send OTP email
    await sendGmail(email, 'Signup OTP', `Your OTP is ${otp}`);
    return res.status(200).json({ message: 'OTP resent to email or Phone.' });
  } catch (error) {
    // console.error('Error in resendOTP:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// Change Password Controller
exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Validate old and new passwords
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ message: 'Old password and new password are required.' });
    }

    const user = req.user; // Assuming req.user contains the authenticated user's data
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if oldPassword matches user's current password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Old password is incorrect.' });
    }

    // Hash the new password and update user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Save updated user profile in the database
    await user.save();

    // Respond with success message
    res.json({ message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Error in changing password:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


exports.forgotPassword = async (req, res) => {
  const { error } = forgotPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Save reset token and expiration to the database
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send reset password link to user's email
    const resetLink = `http://localhost:${process.env.PORT}/api/reset-password?token=${resetToken}&email=${email}`;
    const subject = 'Password Reset Request';
    const text = `Click the link to reset your password: ${resetLink}`;
    const html = `<p>Click the link to reset your password: <a href="${resetLink}">${resetLink}</a></p>`;

    await sendGmail(email, subject, text, html);


    res.status(200).json({ message: 'Password reset link sent successfully' });
  } catch (error) {
    console.error('Error in forgotPassword:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};



exports.resetPassword = async (req, res) => {
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { newPassword } = req.body;
  const { token, email } = req.query;

  try {
    // Find user with the reset token and ensure it hasn't expired
    const user = await User.findOne({
      email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Update user password and clear reset token and expiration
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error in resetPassword:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.deleteAccount = async (req, res) => {
  const { email } = req.body;

  // Delete user account
  await User.deleteOne({ email });

  res.status(200).json({ message: 'User account deleted successfully' });
};


// Upload Profile Image Controller
exports.uploadProfileImage = async (req, res) => {
  try {
    const userId = req.user._id;
    const imagePath = path.join('uploads', req.file.filename);

    // Update the user's profile with the image path
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.profileImage = imagePath;
    await user.save();

    const baseURL = process.env.BASE_URL || `http://localhost:${port}`;
    const fullImageURL = `${baseURL}/uploads/${req.file.filename}`;

    res.json({
      message: 'Profile image uploaded successfully.',
      user: {
        userId: user._id,
        image: fullImageURL,
      }
    });
  } catch (error) {
    console.error('Error in uploading profile image:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


// FRIEND REQUEST LOGIC
exports.sendFriendRequest = async (req, res) => {
  try {
    const senderId = req.user._id;
    const { recipientId } = req.body;

    // Check if sender and recipient are the same
    if (senderId.equals(recipientId)) {
      return res.status(400).json({ message: 'You cannot send a friend request to yourself' });
    }

    // Find sender and recipient users
    const sender = await User.findById(senderId);
    const recipient = await User.findById(recipientId);

    if (!sender) {
      return res.status(404).json({ message: 'User sending request not found' });
    }

    if (!recipient) {
      return res.status(404).json({ message: 'Recipient user not found' });
    }

    // Check if a friend request already exists between the users
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { sender: senderId, recipient: recipientId },
        { sender: recipientId, recipient: senderId }
      ]
    });

    if (existingRequest) {
      return res.status(400).json({ message: 'Friend request already sent or received' });
    }

    // Create a new friend request
    const friendRequest = new FriendRequest({
      sender: senderId,
      recipient: recipientId
    });

    await friendRequest.save();

    res.status(200).json({ message: 'Friend request sent successfully' });
  } catch (error) {
    console.error('Error sending friend request:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Accept Friend Request
exports.acceptFriendRequest = async (req, res) => {
  try {
    const userId = req.user._id;
    const { senderId } = req.body;

    // Find the friend request
    const friendRequest = await FriendRequest.findOne({
      sender: senderId,
      recipient: userId,
      status: 'pending'
    });

    if (!friendRequest) {
      return res.status(400).json({ message: 'Friend request not found' });
    }

    // Update the friend request status
    friendRequest.status = 'accepted';
    await friendRequest.save();

    // Add each other as friends
    const user = await User.findById(userId);
    const sender = await User.findById(senderId);

    if (!user.friends.some(friend => friend.friendId.toString() === senderId.toString())) {
      user.friends.push({ friendId: senderId });
    }

    if (!sender.friends.some(friend => friend.friendId.toString() === userId.toString())) {
      sender.friends.push({ friendId: userId });
    }

    await user.save();
    await sender.save();

    res.status(200).json({ message: 'Friend request accepted successfully' });
  } catch (error) {
    console.error('Error accepting friend request:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Reject Friend Request
exports.rejectFriendRequest = async (req, res) => {
  try {
    const userId = req.user._id;
    const { senderId } = req.body;

    // Find the friend request
    const friendRequest = await FriendRequest.findOneAndDelete({
      sender: senderId,
      recipient: userId,
      status: 'pending'
    });

    if (!friendRequest) {
      return res.status(400).json({ message: 'Friend request not found' });
    }

    res.status(200).json({ message: 'Friend request rejected successfully' });
  } catch (error) {
    console.error('Error rejecting friend request:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// GET FRIEND LIST
exports.getFriendList = async (req, res) => {
  try {
    const userId = req.user._id;
    let page = parseInt(req.query.page) || 1; // Default to page 1 if not provided
    let limit = parseInt(req.query.limit) || 3; // Default to 3 records per page if not provided

    // Constrain the limit to a maximum of 3
    limit = Math.min(limit, 3);

    // Find the user to ensure they exist
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Calculate total number of friends for pagination
    const totalFriendsCount = await User.aggregate([
      { $match: { _id: new mongoose.Types.ObjectId(userId) } },
      { $unwind: '$friends' },
      { $count: 'totalFriends' }
    ]);

    const totalFriends = totalFriendsCount.length > 0 ? totalFriendsCount[0].totalFriends : 0;
    const totalPages = Math.ceil(totalFriends / limit);

    // Check if page exceeds total pages
    if (page > totalPages) {
      return res.status(400).json({ message: `You have exceeded the total pages limit of ${totalPages}` });
    }

    const skip = (page - 1) * limit;

    // Use aggregate to handle the lookup and pagination
    const friendsAggregation = await User.aggregate([
      { $match: { _id: new mongoose.Types.ObjectId(userId) } },
      {
        $lookup: {
          from: 'users',
          let: { friendIds: '$friends.friendId' },
          pipeline: [
            { $match: { $expr: { $in: ['$_id', '$$friendIds'] } } },
            {
              $project: {
                _id: 1,
                fullName: 1,
                email: 1,
                phone: 1,
                countryCode: 1,
                profileImage: 1
              }
            }
          ],
          as: 'friendsDetails'
        }
      },
      { $unwind: '$friendsDetails' },
      { $skip: skip },
      { $limit: limit },
      {
        $project: {
          'friendsDetails._id': 1,
          'friendsDetails.fullName': 1,
          'friendsDetails.email': 1,
          'friendsDetails.phone': 1,
          'friendsDetails.countryCode': 1,
          'friendsDetails.profileImage': 1
        }
      }
    ]);

    res.status(200).json({
      message: 'Friend list retrieved successfully',
      friends: friendsAggregation.map(f => f.friendsDetails),
      currentPage: page,
      totalPages: totalPages
    });
  } catch (error) {
    console.error('Error retrieving friend list:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};



// Controller to fetch the friend requests with pagination
exports.getFriendRequests = async (req, res) => {
  try {
    const userId = req.user._id;
    let page = parseInt(req.query.page) || 1; // Default to page 1 if not provided
    let limit = parseInt(req.query.limit) || 4; // Default to 4 records per page if not provided

    // Constrain the limit to a maximum of 5
    limit = Math.min(limit, 5);

    const skip = (page - 1) * limit;

    // Count total number of friend requests for the user
    const totalFriendRequestsCount = await FriendRequest.countDocuments({
      $or: [
        { sender: new mongoose.Types.ObjectId(userId) },
        { recipient: new mongoose.Types.ObjectId(userId) }
      ]
    });

    const totalPages = Math.ceil(totalFriendRequestsCount / limit);

    // Check if page exceeds total pages
    if (page > totalPages) {
      return res.status(400).json({ message: `You have exceeded the total pages limit of ${totalPages}` });
    }

    const friendRequests = await FriendRequest.aggregate([
      {
        $match: {
          $or: [
            { sender: new mongoose.Types.ObjectId(userId) },
            { recipient: new mongoose.Types.ObjectId(userId) }
          ]
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'sender',
          foreignField: '_id',
          as: 'senderDetails'
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'recipient',
          foreignField: '_id',
          as: 'recipientDetails'
        }
      },
      {
        $unwind: '$senderDetails'
      },
      {
        $unwind: '$recipientDetails'
      },
      {
        $project: {
          _id: 1,
          sender: 1,
          recipient: 1,
          status: 1,
          createdAt: 1,
          'senderDetails.username': 1,
          'senderDetails.email': 1,
          'recipientDetails.username': 1,
          'recipientDetails.email': 1
        }
      },
      { $skip: skip },
      { $limit: limit }
    ]);

    // Categorize the friend requests into sent and received
    const sentFriendRequests = friendRequests.filter(request => request.sender.toString() === userId.toString());
    const receivedFriendRequests = friendRequests.filter(request => request.recipient.toString() === userId.toString());

    res.status(200).json({
      sentFriendRequests,
      receivedFriendRequests,
      currentPage: page,
      totalPages: totalPages
    });
  } catch (error) {
    console.error('Error getting friend requests:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};



// Create Post
exports.createPost = (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ message: err });
    }

    try {
      const userId = req.user._id; // Assuming `req.user` contains the authenticated user
      const { content } = req.body;
      let imageUrl = null;

      if (req.file) {
        imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
      }

      const post = new Post({
        user: userId,
        content: content,
        image: imageUrl
      });

      await post.save();

      res.status(201).json({ message: 'Post created successfully', post });
    } catch (error) {
      console.error('Error creating post:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
};

//Edit Post
exports.editPost = (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ message: err });
    }

    try {
      const userId = req.user._id;
      const { postId } = req.body;
      // let imageUrl = null;

      if (req.file) {
        imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
      }

      // Find the post by userId and postId
      const oldPost = await Post.findOneAndUpdate({ user: userId, _id: postId }, req.body, { new: true });

      if (!oldPost) {
        return res.status(404).json({ message: 'Post not found' });
      }

      res.status(200).json({ message: 'Post updated successfully', post: oldPost });
    } catch (error) {
      console.error('Error editing post:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
};


//Delete Post
exports.deletePost = async (req, res) => {
  try {
    // Ensure user is set in req
    if (!req.user || !req.user._id) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const userId = req.user._id;

    const { postId } = req.body;

    // Check if postId is provided and is a valid ObjectId
    if (!postId || !mongoose.Types.ObjectId.isValid(postId)) {
      return res.status(400).json({ message: 'Invalid or missing Post ID' });
    }

    // Find the post by userId and postId
    const post = await Post.findOne({ _id: postId, user: userId });

    if (!post) {
      return res.status(404).json({ message: 'Post not found or you are not authorized to delete this post' });
    }

    // Delete the post
    await Post.findByIdAndDelete(postId);

    res.status(200).json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

//Get Posts

exports.getPosts = async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user._id);
    const page = parseInt(req.query.page) || 1; // Default to page 1 if not provided
    const limit = parseInt(req.query.limit) || 5; // Default to 5 records per page if not provided
    const skip = (page - 1) * limit;

    // Fetch users who have blocked the current user
    const usersBlockingCurrentUser = await Block.find({ blocked: userId }).select('blocker');
    const blockers = usersBlockingCurrentUser.map(block => block.blocker);

    // Fetch users whom the current user has blocked
    const usersBlockedByCurrentUser = await Block.find({ blocker: userId }).select('blocked');
    const blockedByCurrentUser = usersBlockedByCurrentUser.map(block => block.blocked);

    // Combine both arrays to get the list of users whose posts should be excluded
    const blockedUsers = [...new Set([...blockers, ...blockedByCurrentUser])];

    // Aggregate pipeline to fetch posts and include isLiked status
    const postsWithLikes = await Post.aggregate([
      {
        $match: {
          user: { $nin: blockedUsers } // Exclude posts from users who have blocked the current user or whom the current user has blocked
        }
      },
      { $sort: { createdAt: -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $lookup: {
          from: 'likedislikes',
          let: { postId: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$postId', '$$postId'] },
                    { $eq: ['$userId', userId] }
                  ]
                },
                isLike: true
              }
            },
            { $project: { _id: 0, isLike: 1 } }
          ],
          as: 'likeDislike'
        }
      },
      {
        $addFields: {
          isLiked: { $gt: [{ $size: "$likeDislike" }, 0] }
        }
      },
      {
        $project: {
          _id: 1,
          user: 1,
          content: 1,
          createdAt: 1,
          isLiked: 1
        }
      }
    ]);

    // Count total number of posts excluding blocked users
    const totalPosts = await Post.countDocuments({
      user: { $nin: blockedUsers }
    });

    // Calculate total pages based on the limit
    const totalPages = Math.ceil(totalPosts / limit);

    // Validate if requested page exceeds totalPages
    if (page > totalPages) {
      return res.status(400).json({ message: `You have exceeded the total pages limit which is ${totalPages}` });
    }

    res.status(200).json({
      message: 'Posts retrieved successfully',
      posts: postsWithLikes,
      currentPage: page,
      totalPages
    });
  } catch (error) {
    console.error('Error retrieving posts:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


// Like or Dislike Post
exports.likeOrDislikePost = async (req, res) => {
  try {
    const userId = req.user._id;
    const { isLike, postId } = req.body;

    // Check if postId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(postId)) {
      return res.status(400).json({ message: 'Invalid Post ID' });
    }

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if the user has already liked or disliked the post
    const existingLikeDislike = await LikeDislike.findOne({ postId, userId });

    if (existingLikeDislike) {
      if (existingLikeDislike.isLike === isLike) {
        return res.status(400).json({ message: `You have already ${isLike ? 'liked' : 'disliked'} this post` });
      } else {
        // Update the existing like or dislike
        existingLikeDislike.isLike = isLike;
        await existingLikeDislike.save();
      }
    } else {
      // Create a new like or dislike
      const newLikeDislike = new LikeDislike({
        postId,
        userId,
        isLike
      });
      await newLikeDislike.save();
    }

    res.status(200).json({ message: isLike ? 'Post liked successfully' : 'Post disliked successfully' });
  } catch (error) {
    console.error('Error liking/disliking post:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Comment on a Post
exports.commentOnPost = async (req, res) => {
  try {
    const userId = req.user._id;
    const { postId, content } = req.body;

    // Validate post and user existence
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Create a new comment
    const comment = new Comment({
      postId,
      userId,
      content
    });

    await comment.save();

    res.status(200).json({ message: 'Comment added successfully', comment });
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Block a user
exports.blockUser = async (req, res) => {
  try {
    const blockerId = req.user._id;
    const { blockedId } = req.body;

    // Check if the user is trying to block themselves
    if (blockerId.toString() === blockedId) {
      return res.status(400).json({ message: 'You cannot block yourself' });
    }

    // Validate existence of blocked user
    const blockedUser = await User.findById(blockedId);
    if (!blockedUser) {
      return res.status(404).json({ message: 'User to be blocked not found' });
    }

    // Check if already blocked
    const existingBlock = await Block.findOne({ blocker: blockerId, blocked: blockedId });
    if (existingBlock) {
      return res.status(400).json({ message: 'User already blocked' });
    }

    // Create a new block record
    const block = new Block({
      blocker: blockerId,
      blocked: blockedId
    });

    await block.save();

    res.status(200).json({ message: 'User blocked successfully', block });
  } catch (error) {
    console.error('Error blocking user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Unblock a user
exports.unblockUser = async (req, res) => {
  try {
    const blockerId = req.user._id;
    const { blockedId } = req.body;

    // Validate existence of block record
    const block = await Block.findOne({ blocker: blockerId, blocked: blockedId });
    if (!block) {
      return res.status(404).json({ message: 'Block record not found' });
    }

    await Block.deleteOne({ _id: block._id });

    res.status(200).json({ message: 'User unblocked successfully' });
  } catch (error) {
    console.error('Error unblocking user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


