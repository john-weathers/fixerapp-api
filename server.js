require('dotenv').config();
const express = require('express');
const app = express();
const http = require('http');
const cors = require('cors');
const corsOptions = require('./config/corsOptions');
const allowedOrigins = require('./config/allowedOrigins');
const { logger, logEvents } = require('./middleware/logEvents');
const errorHandler = require('./middleware/errorHandler');
const cookieParser = require('cookie-parser');
const credentials = require('./middleware/credentials');
const mongoose = require('mongoose');
const connectDB = require('./config/dbConn');
const socketHandlerUser = require('./io/socketHandlerUser');
const socketHandlerFixer = require('./io/socketHandlerFixer');
const watcher = require('./io/watcher');
const server = http.createServer(app);
const { Server } = require('socket.io');
const PORT = process.env.PORT || 8500;
const io = new Server(server, {
    cors: {
      origin: allowedOrigins,
      credentials: true,
      optionsSuccessStatus: 200,
    }
  });

const userNsp = io.of('/user');
const fixerNsp = io.of('/fixer');

connectDB();

// app.use(logger);

app.use(credentials);

app.use(cors(corsOptions));

app.use(express.urlencoded({ extended: false }));

app.use(express.json());

app.use(cookieParser());

const publicUserRouter = require('./routes/users/public');
const publicFixerRouter = require('./routes/fixers/public');

app.use('/user', publicUserRouter);
app.use('/fixer', publicFixerRouter);

const privateUserRouter = require('./routes/users/private');
const privateFixerRouter = require('./routes/fixers/private');

app.use('/users', privateUserRouter);
app.use('/fixers', privateFixerRouter);

app.all('*', (req, res, next) => {
    res.sendStatus(404);
})

app.use(errorHandler);

mongoose.connection.once('open', async () => {
    socketHandlerUser(userNsp);
    socketHandlerFixer(fixerNsp);
    await watcher(userNsp, fixerNsp, null, 0);
    server.listen(PORT);
})





