const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// User registration route
router.post('/register', authController.registerUser);

// OTP verification
router.post('/verify-otp', authController.verifyOTP);

// Resend OTP
router.post('/resend-otp', authController.resendOTP);

// User login route
router.post('/login', authController.loginUser);

// User logout route
router.get('/logout', authController.logoutUser);

// Route for forgot password
router.post('/forgot-password', authController.forgotPassword);

// Route for resetting password
router.patch('/reset-password/:token', authController.resetPassword);

// Route for updating password
router.patch('/update-password', authController.updatePassword);

// GET /api/users/:id
router.get('/:id', authController.getUser);

// GET /api/users
router.get('/', authController.getUsers);

// PUT /api/users/:id
router.put('/:id', authController.updateUser);

// DELETE /api/users/:id
router.delete('/:id', authController.deleteUser);


module.exports = router;
