const jwt = require('jsonwebtoken');
require('dotenv').config();
const ROLES = require('../config/roles');
const User = require('../models/User');
const Request = require('../models/Request');
const mongoose = require('mongoose');

const socketHandlerUser = nsp => {
  nsp.use((socket, next) => {
    const authHeader = socket.handshake.headers['authorization'];
    if (!authHeader) return next(new Error('Authorization header required'));
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.USER_ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if (err) return next(new Error('Authentication error'));
            socket.email = decoded.userInfo.email;
            socket.roles = decoded.userInfo.roles;
            const rolesArray = [ROLES.user, ROLES.premiumUser];
            const result = socket.roles.map(role => rolesArray.includes(role)).find(val => val === true);
            if (!result) return next(new Error('Unauthorized'));
            next();
        }
    );
  });

  nsp.on('connection', (socket) => {
    // console.log('a user connected');

    socket.on('disconnect', async () => {
      // console.log('a user disconnected');
      try {
        // clean up any pending requests
        const profile = await User.findOne({ email: socket.email }).exec();
        await Request.deleteOne({ user: profile._id, active: true });
      } catch (err) {
        // console.log(err.message);
      }
    });

    socket.on('new request', async (data, callback) => {
      const { location, address } = data;
      try {
        if (!location?.length || !address) throw new Error('Missing location data');
        const profile = await User.findOne({ email: socket.email }).exec();
        if (!profile || !mongoose.isObjectIdOrHexString(profile._id)) throw new Error('NOK');

        // clean up previous requests before creating a new one
        await Request.deleteOne({ user: profile._id, active: true });

        const newRequest = await Request.create({
          user: profile._id,
          active: true,
          userLocation: { type: 'Point', coordinates: location },
          userAddress: address,
          requestedAt: new Date(),
          extendedOptIn: profile.settings.extendedOptIn,
        });
        socket.join(String(newRequest._id));
        callback({
          status: 'Created',
        });
      } catch (err) {
        if (err.message !== 'Missing location data') {
          callback({
            status: 'NOK',
          })
        } else {
          callback({
            status: err.message,
          })
        }
        
      }
    });

    socket.on('cancel request', async (callback) => {
      try {
        const profile = await User.findOne({ email: socket.email }).exec();
        if (!profile || !mongoose.isObjectIdOrHexString(profile._id)) throw new Error('NOK');

        const deletedRequest = await Request.findOneAndDelete({ user: profile._id, active: true });
        if (!deletedRequest) throw new Error('No pending request found');
        socket.leave(String(deletedRequest._id));
        callback({
          status: 'No content',
        })
      } catch (err) {
        if (err.message !== 'No pending request found') {
          callback({
            status: 'NOK',
          })
        } else {
          callback({
            status: err.message,
          })
        }

      }
    });

    socket.on('current job', (data, callback) => {
      const { jobId } = data;
      socket.join(String(jobId));
      callback({
        status: 'OK',
      });
    });

    socket.on('leave room', (data) => {
      const { jobId } = data;
      socket.leave(String(jobId));
    });

    socket.on('cancel job', async (data, callback) => {
      const { jobId } = data;
      try {
        const cancelledRequest = await Request.findOneAndUpdate({ _id: jobId }, { currentStatus: 'cancelled' });
        if (!cancelledRequest || !mongoose.isObjectIdOrHexString(cancelledRequest._id)) throw new Error('NOK');
        socket.leave(String(cancelledRequest._id));
        callback({
          status: 'OK',
        })
      } catch (err) {
        callback({
          status: 'NOK',
        })
      }
    })

  })
}

module.exports = socketHandlerUser;