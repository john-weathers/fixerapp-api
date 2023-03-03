const mongoose = require('mongoose');
const Fixer = require('../models/Fixer');
const Request = require('../models/Request');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// revisit sameSite cookie settings
// revisit sending roles in login and refresh handlers

const handleRegistration = async (req, res) => {
    const {
        email,
        pwd,
        firstName,
        lastName,
        phoneNumber
    } = req.body;
    const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/;
    if (!PWD_REGEX.test(pwd)) return res.status(400).json({ 'message': 'Password invalid' });
    if (!email || !pwd || !firstName || !lastName || !phoneNumber) return res.status(400).json({ 'message': 'Please submit all required fields' });

    // check for duplicate usernames in the db
    const duplicateUser = await Fixer.findOne({ email }).exec();
    if (duplicateUser) return res.sendStatus(409); //Conflict 

    try {
        //encrypt the password
        const hashedPassword = await bcrypt.hash(pwd, 10);

        //create and store the new Fixer
        const result = await Fixer.create({
            email,
            password: hashedPassword,
            name: {
                first: firstName,
                last: lastName,
            },
            phoneNumber,
        });

        console.log(result);

        res.status(201).json({ 'success': `New fixer at ${email} created!` });
    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
}

const handleLogin = async (req, res) => {
    const cookies = req.cookies;
    console.log(`cookie available at login: ${JSON.stringify(cookies)}`);
    const { email, pwd } = req.body;
    if (!email || !pwd) return res.status(400).json({ 'message': 'Email and password are required for login.' });

    const foundUser = await Fixer.findOne({ email }).exec();
    if (!foundUser) return res.sendStatus(401); // Unauthorized 
    // evaluate password 
    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {
        const roles = Object.values(foundUser.roles).filter(Boolean);
        // create JWTs
        const accessToken = jwt.sign(
            {
                'userInfo': {
                    'email': foundUser.email,
                    roles,
                },
            },
            process.env.FIXER_ACCESS_TOKEN_SECRET,
            { expiresIn: '15s' }
        );
        const newRefreshToken = jwt.sign(
            { 'email': foundUser.email },
            process.env.FIXER_REFRESH_TOKEN_SECRET,
            { expiresIn: '30s' }
        );
        
        let newRefreshTokenArray =
            !cookies?.jwtFixer
                ? foundUser.refreshToken
                : foundUser.refreshToken.filter(rt => rt !== cookies.jwtFixer);

        if (cookies?.jwtFixer) {

            /* 
            Scenario added here: 
                1) Fixer logs in but never uses RT and does not logout 
                2) RT is stolen
                3) If 1 & 2, reuse detection is needed to clear all RTs when Fixer logs in
            */
            const refreshToken = cookies.jwtFixer;
            const foundToken = await Fixer.findOne({ refreshToken }).exec();

            // Detected refresh token reuse!
            if (!foundToken) {
                console.log('attempted refresh token reuse at login!')
                // clear out ALL previous refresh tokens
                newRefreshTokenArray = [];
            }

            res.clearCookie('jwtFixer', { httpOnly: true, sameSite: 'None', secure: true }); // TODO: revisit options
        }

        // Saving refreshToken with current Fixer
        foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
        const result = await foundUser.save();
        console.log(result);

        // Creates Secure Cookie with refresh token
        res.cookie('jwtFixer', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        // Send authorization roles and access token to Fixer
        res.json({ accessToken });

    } else {
        res.sendStatus(401);
    }
}

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwtFixer) return res.sendStatus(401);
    const refreshToken = cookies.jwtFixer;
    res.clearCookie('jwtFixer', { httpOnly: true, sameSite: 'None', secure: true });

    const foundUser = await Fixer.findOne({ refreshToken }).exec();

    // Detected refresh token reuse!
    if (!foundUser) {
        jwt.verify(
            refreshToken,
            process.env.FIXER_REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403); // Forbidden
                console.log('attempted refresh token reuse!')
                const hackedUser = await Fixer.findOne({ email: decoded.email }).exec();
                hackedUser.refreshToken = [];
                const result = await hackedUser.save();
                console.log(result);
            }
        )
        return res.sendStatus(403); // Forbidden
    }

    const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken);

    // evaluate jwt 
    jwt.verify(
        refreshToken,
        process.env.FIXER_REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) {
                console.log('expired refresh token')
                foundUser.refreshToken = [...newRefreshTokenArray];
                const result = await foundUser.save();
                console.log(result);
            }
            if (err || foundUser.email !== decoded.email) return res.sendStatus(403);

            // Refresh token was still valid
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    'userInfo': {
                        'email': decoded.email,
                        roles,
                    },
                },
                process.env.FIXER_ACCESS_TOKEN_SECRET,
                { expiresIn: '15s' }
            );

            const newRefreshToken = jwt.sign(
                { "email": foundUser.email },
                process.env.FIXER_REFRESH_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            // Saving refreshToken with current Fixer
            foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
            const result = await foundUser.save();
            console.log(result);

            // Creates Secure Cookie with refresh token
            res.cookie('jwtFixer', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

            res.json({ accessToken })
        }
    );
}

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken
    
    const cookies = req.cookies;
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
}

const handleGetProfile = async (req, res, next) => {
    const profile = await Fixer.findOne({ email: req.email }).exec();
    if (!profile) return res.redirect('/fixer/logout');

    const profileData = {
        email: profile.email,
        firstName: profile.name.first,
        lastName: profile.name.last,
        phoneNumber: profile.phoneNumber,
        rating: profile.rating,
        premium: !!profile.roles.premiumFixer,
    }

    res.send(profileData);
}

const currentWork = async (req, res, next) => {
    
}

const findWork = async (req, res, next) => {
    const { location } = req.body;
    if (!location.length) return res.sendStatus(400);
    const geojsonPoint = { type: 'Point', coordinates: location } 
    // get profile of fixer or attempt to do so during aggregation?
    const profile = await Fixer.findOne({ email: req.email }).exec();
    if (!profile) return res.redirect('/fixer/logout');
    if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

    try {
        const activeRequests = Request.aggregate([
            {
                $geoNear: {
                    near: geojsonPoint,
                    distanceField: 'distance',
                    maxDistance: 32187, // about 20 miles (default unit meters)
                    query: { 
                        active: true, // filter for active requests only
                        $expr: { $gt: [ '$requestedAt', { $dateSubtract: { startDate: '$$NOW', unit: 'minute', amount: 2 } } ] } // eliminate stale requests
                    },
                }
            },
            { $sort: { requestedAt: 1 } }, // older (non-stale) requests should be satisfied first
            { $limit: 10 }, // only one request will be matched, so we can limit to a pool of eligible candidates (adjust number if needed).
        ]);
        // loop through multiple candidates in the event that a request was matched after aggregation and before updateOne (thinking about a scenario with many requests in a busy area)
        // consider making this a transaction to ensure data is consistent between multiple related operations
        for await (const activeRequest of activeRequests) {
            try {
                // if it turns out values from the updated document are needed, we can use findOneAndUpdate instead (new: true)
                const response = await Request.findOneAndUpdate(
                    { _id: activeRequest._id, active: true },
                    { active: false, currentStatus: 'in progress', trackerStage: 'en route', assignedAt: new Date(), fixer: profile._id },
                    { runValidators: true, new: true, context: 'query', previous: activeRequest.active } // make sure we're not dealing with a stale active value
                )
                    .populate('user', 'name phoneNumber')
                    .exec();
                if (!response) {
                    continue;
                } else {
                    profile.activeJob = activeRequest._id;
                    profile.currentLocation = geojsonPoint;
                    await profile.save();
                    const jobDetails = {

                    }
                    return res.status(201).send(jobDetails)
                }
            } catch (err) {
                continue; // if validation fails (or other error), move to next closest candidate
            }
        }
        res.sendStatus(500);
    } catch (err) {
        res.sendStatus(500);
    }

}

// cancel an in progress job
// api request likely should originate from FixerConfirmation component
const cancelJob = async (req, res, next) => {

}

module.exports = {
    handleLogin,
    handleRegistration,
    handleRefreshToken,
    handleLogout,
    handleGetProfile,
    currentWork,
    findWork,
    cancelJob, 
}