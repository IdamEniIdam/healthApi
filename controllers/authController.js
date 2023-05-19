const User = require('../models/user');
const { sendOTP } = require('../utils/otp');
const { generateOTP } = require('../utils/helpers');
const AppError = require('../utils/appError');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const jwt = require('jsonwebtoken');


// Set your SendGrid API key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);



// User registration
exports.registerUser = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Generate OTP
    const otp = generateOTP(); // You need to implement the generateOTP function


    // Send OTP to user's email
    // await sendOTP(email, otp); // Call the sendOTP function

    // Create a new user
    const user = new User({ name, email, password, otp });
    await user.save();
    res.status(200).json({ message: 'User registered successfully', data: user, status: 'success' });
  } catch (error) {
    next(error);
  }
};


// OTP verification
exports.verifyOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the OTP matches
    if (user.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Update the user's status as verified
    user.verified = true;
    user.otp = null;
    await user.save();

    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    next(error);
  }
};

// Resend OTP
exports.resendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate a new OTP
    const otp = generateOTP();

    // Update the user's OTP and resend it
    user.otp = otp;
    await user.save();

    // Send the new OTP to user's email
    await sendOTP(email, otp);

    res.json({ message: 'New OTP sent successfully' });
  } catch (error) {
    next(error);
  }
};


// User login
exports.loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400))
    }

    const user = await User.findOne({
      $or: [
        {
          email: email,
        }
      ],
    }).select('+password')
    if (!user || !(await user.comparePassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401))
    }

      // Generate JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
        expiresIn: '1h' // Token expires in 1 hour
      });
  
      // Include token and its expiration in the user data
      const userData = {
        _id: user._id,
        name: user.name,
        email: user.email,
        token: token,
        tokenExpiresAt: Date.now() + 3600000 // Token expiration timestamp
      };

    res.json({ message: 'User logged in successfully', data: userData,  status: 'success'  });
  } catch (error) {
    next(error);
  }
};

// Middleware for handling forgot password requests
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate password reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Send password reset email to the user
    const resetURL = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    const message = `Forgot your password? Your new password and passwordConfirm to: ${resetURL}`;
    await sgMail.send({
      to: user.email,
      from: 'idameni89@gmail.com',
      subject: 'Password Reset',
      text: message,
    });

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    next(error);
  }
};

// Middleware for resetting the user's password
exports.resetPassword = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password, passwordConfirm } = req.body;

    // Hash the reset token to compare with the stored token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find the user by the reset token and check if the token is valid
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Update the user's password
    user.password = password;
    user.passwordConfirm = passwordConfirm;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    next(error);
  }
};

// Middleware for updating the user's password
exports.updatePassword = async (req, res, next) => {
  try {
    const { email, currentPassword, newPassword, newPasswordConfirm } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the current password is correct
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect current password' });
    }

    // Update the user's password
    user.password = newPassword;
    user.passwordConfirm = newPasswordConfirm;
    await user.save();

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    next(error);
  }
};

// Get single user
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ data: user });
  } catch (error) {
    next(error);
  }
};

// Get all users
exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    res.json({ data: users });
  } catch (error) {
    next(error);
  }
};

// Update user
exports.updateUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User updated successfully', data: user });
  } catch (error) {
    next(error);
  }
};

// Delete user
exports.deleteUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    next(error);
  }
};


// User logout
exports.logoutUser = (req, res) => {
  res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    })
  
    res.status(200).json({ status: 'User logged out successfully' })
};


 exports.checkUserExists = async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  req.user = user;
  next();
};


