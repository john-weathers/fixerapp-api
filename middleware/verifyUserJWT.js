const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyUserJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.USER_ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if (err) return res.sendStatus(403);
            req.email = decoded.userInfo.email;
            req.roles = decoded.userInfo.roles;
            next();
        }
    );
}

module.exports = verifyUserJWT;