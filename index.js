// index.js
const express = require('express');
const bodyParser = require('body-parser');
const connectDB = require('./config/database') // DB connection
const dotenv = require('dotenv')
const cors = require('cors');
const authMiddleware = require('./middleware/auth')
const errorMiddleware = require('./middleware/error')
const authRoutes = require('./routes/authRoutes');


dotenv.config()
const port = 8000
connectDB() 
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '200mb' }))
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.get('/', (req, res) => {
  res.json({
    status: 'success',
    message:
      'Health API. Coneccted',
  })
})

// Routes
app.use('/api/users', authRoutes);

app.use('*', authMiddleware)
app.use(errorMiddleware)

  const server = app.listen(port, () =>
  console.log(`App running on port ${port}... 🔥🔥`)
  )

  // Handle Unhandled Rejections
  process.on('unhandledRejection', (error) => {
  console.log('UNHANDLED REJECTION!, Shutting Down... 💥💥⚡️✨')
  console.log(error.name, error.message)
  server.close(() => {
    process.exit(1)
  })
  })