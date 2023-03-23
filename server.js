require('dotenv').config();
const express = require('express');
const app = express();
const http = require('http');
const cors = require('cors');
const corsOptions = require('./config/corsOptions');
const allowedOrigins = require('./config/allowedOrigins');
const { logger, logEvents } = require('./middleware/logEvents');
const errorHandler = require('./middleware/errorHandler');
const verifyJWT = require('./middleware/verifyFixerJWT');
const cookieParser = require('cookie-parser');
const credentials = require('./middleware/credentials');
const mongoose = require('mongoose');
const connectDB = require('./config/dbConn');
const server = http.createServer(app);
const { Server } = require('socket.io');
const PORT = process.env.PORT || 8500;
const io = new Server(server, {
    cors: { // may be able to delete or reduce previously included cors options
      origin: allowedOrigins,
      credentials: true,
      optionsSuccessStatus: 200,
      // preflightContinue: true, don't think this is needed but keep an eye on it
    }
  });

const userNsp = io.of('/user');
const fixerNsp = io.of('/fixer');

// TODO NEXT ON SERVER SIDE: build out namespace events, watcher function details, update controllers as needed
// TODO NEXT ON CLIENT SIDE: on client side refactor QF components, FixerConfirmation component, build out UserConfirmation component

// need to add socket handlers and watcher (passing in relevant variables)
// I think anywhere below database connection should be fine
// also need to update app.listen to server.listen
// just need to double check/research positioning for all of the above

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
const publicUserRouter = require('./routes/users/public');
const publicFixerRouter = require('./routes/fixers/public');

app.use('/user', publicUserRouter);
app.use('/fixer', publicFixerRouter);

// private routes
const privateUserRouter = require('./routes/users/private');
const privateFixerRouter = require('./routes/fixers/private');

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





