const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyUserJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);
    console.log(authHeader); // Bearer token
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.USER_ACCESS_TOKEN_SECRET, // create secret key
        (err, decoded) => {
            if (err) console.log('VERIFY JWT ERROR OCCURING');
            if (err) return res.sendStatus(403); //invalid token
            req.email = decoded.userInfo.email;
            req.roles = decoded.userInfo.roles;
            next();
        }
    );
}

module.exports = verifyUserJWT;