const User = require('../models/User');
const Fixer = require('../models/Fixer');
const Request = require('../models/Request');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const COOKIE_AGE = 24 * 60 * 60 * 1000;

// TODO: need to update all previous location properties for Request queries and any fixer location properties (which will now live on Request model)

// revisit sameSite cookie settings
// revisit sending roles in login and refresh handlers

// public controllers
const handleRegistration = async (req, res) => {
    const {
        email,
        pwd,
        firstName,
        lastName,
        phoneNumber
    } = req.body;
    const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/;
    if (!PWD_REGEX.test(pwd)) return res.status(400).json({'message': 'Password invalid'});
    if (!email || !pwd || !firstName || !lastName || !phoneNumber) return res.status(400).json({ 'message': 'Required for registration: email, password, first and last name, phone number' });

    // check for duplicate usernames in the db
    const duplicateUser = await User.findOne({ email }).exec();
    if (duplicateUser) return res.sendStatus(409); //Conflict 

    try {
        //encrypt the password
        const hashedPassword = await bcrypt.hash(pwd, 10);
        
        //create and store the new user
        const result = await User.create({
            email,
            password: hashedPassword,
            name: {
                first: firstName,
                last: lastName,
            },
            phoneNumber,
        });

        console.log(result);

        res.status(201).json({ 'success': `New user at ${email} created!` });
    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
}

const handleLogin = async (req, res) => {
    const cookies = req.cookies;
    console.log(`cookie available at login: ${JSON.stringify(cookies)}`);
    const { email, pwd } = req.body;
    if (!email || !pwd) return res.status(400).json({ 'message': 'Email and password are required for login.' });

    const foundUser = await User.findOne({ email }).exec();
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
                    'roles': roles,
                },
            },
            process.env.USER_ACCESS_TOKEN_SECRET,
            { expiresIn: '10s' }
        );
        const newRefreshToken = jwt.sign(
            { 'email': foundUser.email },
            process.env.USER_REFRESH_TOKEN_SECRET,
            { expiresIn: '30s' }
        );
        
        let newRefreshTokenArray =
            !cookies?.jwtUser
                ? foundUser.refreshToken
                : foundUser.refreshToken.filter(rt => rt !== cookies.jwtUser);

        if (cookies?.jwtUser) {

            /* 
            Scenario added here: 
                1) User logs in but never uses RT and does not logout 
                2) RT is stolen
                3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
            */
            const refreshToken = cookies.jwtUser;
            const foundToken = await User.findOne({ refreshToken }).exec();

            // Detected refresh token reuse!
            if (!foundToken) {
                console.log('attempted refresh token reuse at login!')
                // clear out ALL previous refresh tokens
                newRefreshTokenArray = [];
            }

            res.clearCookie('jwtUser', { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE }); // TODO: revisit options
        }

        // Saving refreshToken with current user
        
        foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
        foundUser.prevTokens.refreshTokens = [];
        await foundUser.save();

        // Creates Secure Cookie with refresh token
        res.cookie('jwtUser', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE });

        // Send authorization roles and access token to user
        res.status(200).send({ accessToken });

    } else {
        res.sendStatus(401);
    }
}

const handleRefreshToken = async (req, res) => {
    console.log('handling refresh');
    const cookies = req.cookies;
    if (!cookies?.jwtUser) return res.sendStatus(401);
    const refreshToken = cookies.jwtUser;
    
  
    try {
        const foundUser = await User.findOne({ refreshToken }).exec();
        // To handle useEffect development behavior
        // Better than removing strict mode for the remainder of development in my opinion
        // In production would keep else block behavior in case of !foundUser
        // could use tweaking, not perfect yet, but good enough for development purposes going forward in my opinion
        if (!foundUser) {
            try {
                const refreshCheck = await User.findOne({ 'prevTokens.refreshTokens': refreshToken }).exec();
                console.log(refreshCheck);
                if (refreshCheck && new Date() - refreshCheck.prevTokens.lastRefresh < 1000) {
                    jwt.verify(
                        refreshToken,
                        process.env.USER_REFRESH_TOKEN_SECRET,
                        async (err, decoded) => {
                            if (err) {
                                console.log('expired refresh token on double refresh')
                                return res.sendStatus(403);
                            }
                            const prevTokenDetails = {
                                accessToken: refreshCheck.prevTokens.accessToken
                            }
                            const prevArr = refreshCheck.prevTokens.refreshTokens;
                            const refreshArrLength = prevArr.length;
                            if (refreshArrLength > 10) {
                                refreshCheck.prevTokens.refreshTokens.pop(); // instead of popping cut to ten
                                await refreshCheck.save();
                            }
                            if (res.headersSent) return;
                            return res.send(prevTokenDetails);
                                
                        }
                    );
                    if (res.headersSent) return;
                    res.sendStatus(403);
                } else {
                    res.clearCookie('jwtUser', { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE });
                    jwt.verify(
                        refreshToken,
                        process.env.USER_REFRESH_TOKEN_SECRET,
                        async (err, decoded) => {
                            if (err) return res.sendStatus(403); // Forbidden
                            console.log('attempted refresh token reuse!')
                            const hackedUser = await User.findOne({ email: decoded.email }).exec();
                            hackedUser.refreshToken = [];
                            const result = await hackedUser.save();
                        }
                    );
                    if (res.headersSent) return;
                    res.sendStatus(403);
                }
            } catch (err) {
                console.log(err.message);
            }
        }
        if (res.headersSent) return;
        res.clearCookie('jwtUser', { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE });
        console.log(foundUser?.refreshToken);
        console.log(refreshToken);
        
        const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken);
    
        // evaluate jwt 
        jwt.verify(
            refreshToken,
            process.env.USER_REFRESH_TOKEN_SECRET,
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
                            'roles': roles,
                        },
                    },
                    process.env.USER_ACCESS_TOKEN_SECRET,
                    { expiresIn: '10s' }
                );
    
                const newRefreshToken = jwt.sign(
                    { 'email': foundUser.email },
                    process.env.USER_REFRESH_TOKEN_SECRET,
                    { expiresIn: '30s' }
                );
                // Saving refreshToken with current user
                const prevArr = foundUser.prevTokens.refreshTokens;
                const refreshArrLength = prevArr.length;
                if (refreshArrLength > 10) {
                    foundUser.prevTokens.refreshTokens.pop();
                }
                foundUser.prevTokens.refreshTokens.unshift(refreshToken);
                foundUser.prevTokens.accessToken = accessToken;
                foundUser.prevTokens.lastRefresh = new Date();
                foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
                await foundUser.save();
    
                // Creates Secure Cookie with refresh token
                res.cookie('jwtUser', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE });
    
                return res.status(200).send({ accessToken });
            }
        );
    } catch (err) {
        console.log(err.message);
        if (res.headersSent) return;
        res.sendStatus(500);
    }
    
  }

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken

    const cookies = req.cookies;
    console.log(cookies);
    if (!cookies?.jwtUser) return res.sendStatus(204); // No content
    const refreshToken = cookies.jwtUser;

    // refresh token in db?
    console.log(refreshToken);
    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) {
        // trying to mitigate scenario where a refresh fires just before logout
        // in this case, cookie could be stale and not match the most recently added RT in db
        try {
            const refreshCheck = await User.findOne({ 'prevTokens.refreshTokens': refreshToken }).exec();
            console.log(refreshCheck);
            // if the cookie RT matches a previous RT, and a refresh has happened within the last second, we remove the last RT in db
            if (refreshCheck && new Date() - refreshCheck.prevTokens.lastRefresh < 1000) {
                refreshCheck.refreshToken.pop();
                await refreshCheck.save();
            }
        } catch (err) {
            console.log(err.message);
        }
        // cookie is cleared either way
        res.clearCookie('jwtUser', { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE }); // revisit clearCookie options
        return res.sendStatus(204);
    }
    // Delete refreshToken in db
    foundUser.refreshToken = foundUser.refreshToken.filter(rt => rt !== refreshToken);;
    const result = await foundUser.save();
    console.log(result);

    res.clearCookie('jwtUser', { httpOnly: true, secure: true, sameSite: 'None', maxAge: COOKIE_AGE });
    res.sendStatus(204);
}

// private controllers
const handleGetProfile = async (req, res, next) => {
    try {
        const profile = await User.findOne({ email: req.email }).exec();
        if (!profile) return res.sendStatus(401);

        const profileData = {
            email: profile.email,
            firstName: profile.name.first,
            lastName: profile.name.last,
            phoneNumber: profile.phoneNumber,
            rating: profile.rating,
            premium: !!profile.roles.premiumUser,
        }
        res.send(profileData);
    } catch (err) {
        res.status(500).send(err.message);
    }
}

// replaced with websocket functionality
const fixRequest = async (req, res, next) => {
    const { location, address } = req.body;
    let responseSent = false;
    if (!location.length || !address) return res.sendStatus(400);

    try {
        const profile = await User.findOne({ email: req.email }).exec();
        // perhaps should res.sendStatus(401) if !profile? ...redirect to logout might not be ideal design pattern here
        if (!profile) return res.redirect('/user/logout'); 
        if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

        // logic elsewhere should prevent user creating additional requests if they already have a request in progress
        // revisit if this needs to be beefed up to deal with those type of edge cases
        const newRequest = await Request.findOneAndUpdate(
            { user: profile._id, active: true },
            { user: profile._id, location: { type: 'Point', coordinates: location }, userAddress: address, active: true, requestedAt: new Date() },
            { upsert: true }
        );
        if (!mongoose.isObjectIdOrHexString(newRequest._id)) return res.sendStatus(500);

        const pipeline = [
            {
              $match: {
                operationType: 'update',
                'documentKey._id': newRequest._id,
                'updateDescription.updatedFields.currentStatus': 'in progress',
                'updateDescription.updatedFields.active': false,
              }
            }
          ];

        const changeStream = Request.watch(pipeline, { fullDocument: 'updateLookup' }).on('change', change => {
            const jobDetails = {
                userLocation: change.fullDocument.location.coordinates,
                userAddress: change.fullDocument.userAddress,
                fixerLocation: change.fullDocument.fixer.currentLocation.coordinates,
                trackerStage: change.fullDocument.trackerStage,
                name: change.fullDocument.fixer.name.first,
                phoneNumber: change.fullDocument.fixer.phoneNumber,
                eta: change.fullDocument?.route?.duration, // will be in seconds, conversions can happen on f/e
            }
            res.status(200).send(jobDetails);
            responseSent = true;
        });

        const closeChangeStream = () => {
            return new Promise((resolve) => {
                setTimeout(async () => {
                    console.log('Closing the change stream');
                    const currentRequest = await Request.findOne({ user: profile._id, active: true });
                    if (!responseSent && newRequest.requestedAt === currentRequest?.requestedAt) res.sendStatus(408);
                    changeStream.close();
                    resolve();
                }, 120000);
            });
        }

        await closeChangeStream();

        /*if (!response.modifiedCount && !response.upsertedCount) return res.sendStatus(500);
        res.status(201).send('request successfully created!');*/

        // theoretically can use scheduled triggers to keep the requests collection lean (e.g., active requests that are older than x time should be changed to 'failed'
        // and/or can move any requests past a certain age to a separate archive collection, etc.)
        // this may reduce or eliminate the need for certain refs/population


    } catch (err) {
        res.status(500).send(err.message);
    }
}

const currentRequest = async (req, res, next) => {
    // consider adding userEmail as a separate property for Request model if we need/want to reduce number of database requests
    // tradeoff is adding some redundancy to each Request document
    try {
        const profile = await User.findOne({ email: req.email }).exec();
        // perhaps should res.sendStatus(401) if !profile? ...redirect to logout might not be ideal design pattern here
        if (!profile) return res.sendStatus(401);
        if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

        const activeJob = await Request.findOne({ user: profile._id, currentStatus: 'in progress' })
            .populate('fixer', 'name phoneNumber rating currentLocation') // in production it may be best to wait to send currentLocation for privacy reasons
            .exec();
        if (!activeJob) return res.sendStatus(404);
        const jobDetails = {
            jobId: activeJob._id,
            userLocation: activeJob.location.coordinates,
            userAddress: activeJob.userAddress,
            fixerLocation: activeJob.fixer.currentLocation.coordinates,
            currentStatus: activeJob.currentStatus,
            assignedAt: activeJob.assignedAt,
            trackerStage: activeJob.trackerStage,
            fixerName: activeJob.fixer.name.first,
            fixerRating: activeJob.fixer?.rating,
            phoneNumber: activeJob.fixer.phoneNumber,
            eta: activeJob.eta, // will be in seconds, conversions can happen on f/e
        }
        res.status(200).send(jobDetails);
    } catch (err) {
        res.status(500).send(err.message);
    }

}

// replaced with websocket functionality
const cancelRequest = async (req, res, next) => {
    const profile = await User.findOne({ email: req.email }).exec();
    // perhaps should res.sendStatus(401) if !profile? ...redirect to logout might not be ideal design pattern here
    if (!profile) return res.sendStatus(401);
    if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

    const response = await Request.deleteOne({ user: profile._id, active: true });

    if (!response.deletedCount) return res.sendStatus(500);
    res.status(204).send('request successfully deleted')
}

const handleQuoteDecision = async (req, res, next) => {
    const { accept, jobId } = req.body;
    try {
        if (accept) {
            const request = await Request.findOne({ _id: jobId }).exec();
            if (!request) return res.sendStatus(404);

            if (!request?.workStartedAt) {
                const response = await Request.updateOne({ _id: jobId }, { 'quote.pending': false, trackerStage: 'fixing', workStartedAt: new Date() });
                if (!response.modifiedCount) return res.sendStatus(404);
            } else {
                const response = await Request.updateOne({ _id: jobId }, { 'quote.pending': false });
                if (!response.modifiedCount) return res.sendStatus(404);
            }
            res.sendStatus(200);
        } else {
            const response = await Request.updateOne({ _id: jobId }, { 'quote.pending': false });
            if (!response.modifiedCount) return res.sendStatus(404);
            res.sendStatus(200);
        }
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleRating = async (req, res, next) => {
    const { jobId, rating } = req.body;
    if (!rating || rating < 1 || rating > 5) res.sendStatus(400);

    try {
        const { fixer } = await Request.findOne({ _id: jobId }).exec();
        if (!fixer) res.sendStatus(404);

        const response = await Fixer.updateOne({ _id: jobId }, { $push: { ratings: rating } });
        if (!response.modifiedCount) res.sendStatus(404);
        res.sendStatus(200);
    } catch (err) {
        res.sendStatus(500);
    }
}

module.exports = {
    handleRegistration,
    handleLogin,
    handleRefreshToken,
    handleLogout,
    handleGetProfile,
    fixRequest,
    currentRequest,
    cancelRequest,
    handleQuoteDecision,
    handleRating,
}