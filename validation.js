const Joi = require('joi');

const signupSchema = Joi.object({
  email: Joi.string().email().optional(),
  phone: Joi.string().max(10).min(10).optional().when('email', { is: Joi.exist(), then: Joi.forbidden() }),
  countryCode: Joi.string().optional(),
  password: Joi.string().min(6).required(),
}).xor('email', 'phone');

const verifySignupOTPSchema = Joi.object({
  email: Joi.string().email().optional(),
  phone: Joi.string().optional(),
  countryCode: Joi.string().optional(),
  otp: Joi.string().length(6).required(), // Assuming OTP is a 6-digit string
});
 
const loginSchema = Joi.object({
  email: Joi.string().email().optional(),
  phone: Joi.string().max(10).min(10).optional(),
  countryCode: Joi.string().optional(),
  password: Joi.string().min(6).required(),
}).xor('email', 'phone');

const verifyLoginOTPSchema = Joi.object({
  phone: Joi.string().required(),
  otp: Joi.string().required(),
});



const updateProfileSchema = Joi.object({
  fullName: Joi.string().optional(),
  address: Joi.string().optional(),
  phone: Joi.string().max(10).min(10).optional(),
  countryCode: Joi.string().required(),
  email: Joi.string().email().optional(),
}).or('email', 'phone');


const resendOTPSchema = Joi.object({
  email: Joi.string().email().optional(),
  phone: Joi.string().max(10).min(10).optional(),
  countryCode: Joi.string().optional(),
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetPasswordSchema = Joi.object({
  newPassword: Joi.string().min(6).required(),
});

module.exports = {
  signupSchema,
  verifySignupOTPSchema,
  loginSchema,
  verifyLoginOTPSchema,
  updateProfileSchema,
  resendOTPSchema,
  resetPasswordSchema,
  forgotPasswordSchema,
  };