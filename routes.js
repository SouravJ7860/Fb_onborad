const express = require('express');
const router = express.Router();
const upload = require('./config/multerConfig');
const {
  signup,verifySignupOTP,login,verifyLoginOTP,getProfile,updateProfile,resendOTP,changePassword,forgotPassword,resetPassword,deleteAccount,uploadProfileImage,sendFriendRequest,acceptFriendRequest,rejectFriendRequest,getFriendList,getFriendRequests,createPost, editPost, deletePost, getPosts,likeOrDislikePost,commentOnPost, blockUser , unblockUser
 
} = require('./controller');


const checkUserExists  = require('./userMiddleware').checkUserExists
const authToken  =  require('./authmiddleware') ;

// Signup Routes
router.post('/signup', checkUserExists, signup);
router.post('/verify-signup', verifySignupOTP);
router.post('/resend-otp' , resendOTP);

// Login Route
router.post('/login', login);
router.post('/verify-login-otp', verifyLoginOTP);

// Profile Routes
router.get('/profile',authToken, getProfile);
router.patch('/Update-profile',authToken, updateProfile);

// Other Routes (e.g., forgot password)
router.post('/change-password', authToken, changePassword);
router.post('/forgot-password', authToken,forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/delete-account',deleteAccount);

// POST route for uploading profile image
router.post('/upload-profile-image',authToken,  upload.single('image'), uploadProfileImage);


// Friend Request Routes 
router.post('/send-friend-request',   authToken , sendFriendRequest);
router.post('/accept-friend-request', authToken , acceptFriendRequest);
router.post('/reject-friend-request', authToken ,  rejectFriendRequest);
router.get('/friendList', authToken , getFriendList);
router.get('/friend-requests', authToken, getFriendRequests);

// User POST
router.post('/createPost', authToken , createPost);
router.put('/editPost' , authToken , editPost);
router.delete('/deletePost' ,authToken, deletePost);
router.get('/getPosts', authToken ,getPosts);
router.post('/postLikeorDislike', authToken, likeOrDislikePost);
router.post('/comment', authToken, commentOnPost); 
// Route to block a user
router.post('/block', authToken, blockUser);
// Route to unblock a user
router.post('/unblock', authToken, unblockUser);


module.exports = router;
