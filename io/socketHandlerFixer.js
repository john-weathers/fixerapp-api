const jwt = require('jsonwebtoken');
require('dotenv').config();
const ROLES = require('../config/roles');
const Fixer = require('../models/Fixer');
const Request = require('../models/Request');
const mongoose = require('mongoose');

const socketHandlerFixer = nsp => {
  nsp.use((socket, next) => {
    const authHeader = socket.handshake.headers['authorization'];
    if (!authHeader) return next(new Error('Authorization header required'));
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.FIXER_ACCESS_TOKEN_SECRET, // create secret key
        (err, decoded) => {
            if (err) return next(new Error('Authentication error')); //invalid token
            socket.email = decoded.userInfo.email;
            socket.roles = decoded.userInfo.roles;
            const rolesArray = [ROLES.fixer, ROLES.premiumFixer];
            const result = socket.roles.map(role => rolesArray.includes(role)).find(val => val === true);
            if (!result) return next(new Error('Unauthorized'));
            next();
        }
    );
  });

  nsp.on('connection', (socket) => {
    console.log('a user connected');

    socket.on('disconnect', () => {
      console.log('a user disconnected');
    });

    socket.on('work found', async (callback) => {
      try {
        const { activeJob } = await Fixer.findOne({ email: socket.email }).exec();
        if (!activeJob) throw new Error('No job found')
        socket.join(String(activeJob));
        callback({
          status: 'OK'
        });
      } catch (err) {
        callback({
          status: 'NOK',
        })
      }
    });

    socket.on('current job', (data, callback) => {
      const { jobId } = data;
      socket.join(String(jobId));
      callback({
        status: 'OK',
      });
    })

    // update fixer location
    socket.on('update location', async (data) => {
      const { location, jobId } = data;
      const geojsonPoint = {
        type: 'Point',
        coordinates: location,
      }
      try {
        await Request.updateOne({ _id: jobId }, { fixerLocation: geojsonPoint });
      } catch (err) {
        console.log(err.message) // error handling may need to be more extensive...keep an eye on in testing
      }
    });

    socket.on('arriving', async (jobId, callback) => {
      try {
        const response = await Request.updateOne({ _id: jobId }, { trackerStage: 'arriving' });
        if (response.modifiedCount) callback({
          status: 'OK',
        });
      } catch (err) {
        callback({
          status: 'NOK',
        })
      }
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

module.exports = socketHandlerFixer;