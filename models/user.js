const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  name: {
    type: String,
    required: [true, 'Please provide your name!'],
    minlength: [3, 'Name should be more than 3 characters.'],
  },
  profilePicUrl: { type: Object },
  email: {
    type: String,
    required: [true, 'Please provide your email!'],
    unique: true
  },
  password: {
    type: String,
    required: true,
    select: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next()

  this.password = await bcrypt.hash(this.password, 12)

  next()
})

// Compare provided password with the stored hashed password

userSchema.methods.comparePassword = async function (
  otherPassword,
  userPassword
) {
  return await bcrypt.compare(otherPassword, userPassword)
}



module.exports = mongoose.model('User', userSchema);
