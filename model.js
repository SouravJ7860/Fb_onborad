const mongoose = require('mongoose');


const friendSchema = new mongoose.Schema({
  friendId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  addedAt: { type: Date, default: Date.now }
});


const userSchema = new mongoose.Schema({
  fullName: { type: String, required: false },
  email: { type: String, required: function() { return !this.phone; }, unique: true , sparse: true },
  phone: { type: String, required: function() { return !this.email; }, unique: true ,  sparse: true },
  countryCode: { type: String , required: false },
  address: { type: String, required: false },
  password: { type: String, required: true },
  friends: [friendSchema],
  profileImage: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date }, 
  verified: {type: Boolean, default: false},
  }, { timestamps: true });

  
const otpSchema = new mongoose.Schema({
  email: {type: String,required: true},
  phone: {type: String, sparse: true },
  otp: {type: String,required: true},
  otpExpires: {type : Date, required: true},
});

const postSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: false },
  image: { type: String, required: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});


// Define the FriendRequest schema
const friendRequestSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
})

const likeDislikeSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isLike: { type: Boolean, required: true },   
  createdAt: { type: Date, default: Date.now }
});

const commentSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const blockSchema = new mongoose.Schema({
  blocker: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  blocked: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});


module.exports = {
  User: mongoose.model('User', userSchema),
  OTP: mongoose.model('OTP', otpSchema),
  FriendRequest : mongoose.model('FriendRequest', friendRequestSchema),
  Post : mongoose.model('Post' , postSchema),
  LikeDislike : mongoose.model('LikeDislike',likeDislikeSchema),
  Friend : mongoose.model('Friend' ,friendSchema),
  Comment : mongoose.model('Comment' , commentSchema ),
  Block : mongoose.model('Block' , blockSchema )
};