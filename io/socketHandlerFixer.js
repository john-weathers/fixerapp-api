const jwt = require('jsonwebtoken');
require('dotenv').config();
const ROLES = require('../config/roles');
const Fixer = require('../models/Fixer');
const circle = require('@turf/circle').default;
const booleanPointInPolygon = require('@turf/boolean-point-in-polygon').default;

const fixerSocketHandler = nsp => {
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
    })

    // update fixer location
    socket.on('update location', async (data) => {
      const { location, jobId } = data;
      try {
        
      } catch (err) {
        
      }
    })

    socket.on('arriving', async (jobId, callback) => {
      try {

      } catch (err) {

      }
    })
  })
}

module.exports = fixerSocketHandler;