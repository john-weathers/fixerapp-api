const User = require('../models/User');
const Fixer = require('../models/Fixer')

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken
    const cookies = req.cookies;
    const { userType } = req.body;

    if (userType === 'user') {
        if (!cookies?.jwtUser) return res.sendStatus(204); // No content
        const refreshToken = cookies.jwtUser;

        // refresh token in db?
        const foundUser = await User.findOne({ refreshToken }).exec();
        if (!foundUser) {
            res.clearCookie('jwtUser', { httpOnly: true, sameSite: 'None', secure: true }); // revisit clearCookie options
            return res.sendStatus(204);
        }
    
        // Delete refreshToken in db
        foundUser.refreshToken = foundUser.refreshToken.filter(rt => rt !== refreshToken);;
        const result = await foundUser.save();
        console.log(result);
    
        res.clearCookie('jwtUser', { httpOnly: true, sameSite: 'None', secure: true });
        res.sendStatus(204);

    } else if (userType === 'fixer') {
        if (!cookies?.jwtFixer) return res.sendStatus(204); // No content
        const refreshToken = cookies.jwtFixer;

        // refresh token in db?
        const foundUser = await Fixer.findOne({ refreshToken }).exec();
        if (!foundUser) {
            res.clearCookie('jwtFixer', { httpOnly: true, sameSite: 'None', secure: true }); // revisit clearCookie options
            return res.sendStatus(204);
        }
    
        // Delete refreshToken in db
        foundUser.refreshToken = foundUser.refreshToken.filter(rt => rt !== refreshToken);;
        const result = await foundUser.save();
        console.log(result);
    
        res.clearCookie('jwtFixer', { httpOnly: true, sameSite: 'None', secure: true });
        res.sendStatus(204);

    } else {
        res.status(400).json({ 'message': 'User type must be specified.' });
    }
}

module.exports = { handleLogout }