require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const corsOptions = require('./config/corsOptions');
const { logger, logEvents } = require('./middleware/logEvents');
const errorHandler = require('./middleware/errorHandler');
const verifyJWT = require('./middleware/verifyUserJWT');
const cookieParser = require('cookie-parser');
const credentials = require('./middleware/credentials');
const mongoose = require('mongoose');
const connectDB = require('./config/dbConn');
const PORT = process.env.PORT || 8500;

// connect to MongoDB
connectDB();

// log request data
app.use(logger);

// accept cookies and other credentials if origin is allowed
app.use(credentials);

app.use(cors(corsOptions));

app.use(express.urlencoded({ extended: false }));

app.use(express.json());

app.use(cookieParser());

// public routes
const publicUserRouter = require('./routes/usersPublic');
const publicFixerRouter = require('./routes/fixersPublic');

app.use('/user', publicUserRouter);
app.use('/fixer', publicFixerRouter);

// private routes
const privateUserRouter = require('./routes/usersPrivate');
const privateFixerRouter = require('./routes/fixersPrivate');

app.use('/users', privateUserRouter);
app.use('/fixers', privateFixerRouter);

app.all('*', (req, res, next) => {
    res.sendStatus(404);
})

app.use(errorHandler);

mongoose.connection.once('open', () => {
    console.log('Connected to MongoDB');
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
})





