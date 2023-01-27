const jwt = require('jsonwebtoken');
require('dotenv').config();

// depending on front end design may need to update jwt verification and bifurcate controllers completely
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);
    console.log(authHeader); // Bearer token
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET, // create secret key
        (err, decoded) => {
            if (err) return res.sendStatus(403); //invalid token
            req.email = decoded.email;
            next();
        }
    );
}

module.exports = verifyJWT;