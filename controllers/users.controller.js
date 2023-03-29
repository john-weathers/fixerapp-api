const User = require('../models/User');
const Fixer = require('../models/Fixer');
const Request = require('../models/Request');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

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
                    roles,
                },
            },
            process.env.USER_ACCESS_TOKEN_SECRET,
            { expiresIn: '15s' }
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

            res.clearCookie('jwtUser', { httpOnly: true, sameSite: 'None', secure: true }); // TODO: revisit options
        }

        // Saving refreshToken with current user
        foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
        const result = await foundUser.save();
        console.log(result);

        // Creates Secure Cookie with refresh token
        res.cookie('jwtUser', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        // Send authorization roles and access token to user
        res.json({ accessToken });

    } else {
        res.sendStatus(401);
    }
}

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwtUser) return res.sendStatus(401);
    const refreshToken = cookies.jwtUser;
    res.clearCookie('jwtUser', { httpOnly: true, sameSite: 'None', secure: true });

    const foundUser = await User.findOne({ refreshToken }).exec();

    // Detected refresh token reuse!
    if (!foundUser) {
        jwt.verify(
            refreshToken,
            process.env.USER_REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403); // Forbidden
                console.log('attempted refresh token reuse!')
                const hackedUser = await User.findOne({ email: decoded.email }).exec();
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
                        roles,
                    },
                },
                process.env.USER_ACCESS_TOKEN_SECRET,
                { expiresIn: '15s' }
            );

            const newRefreshToken = jwt.sign(
                { "email": foundUser.email },
                process.env.USER_REFRESH_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            // Saving refreshToken with current user
            foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
            const result = await foundUser.save();
            console.log(result);

            // Creates Secure Cookie with refresh token
            res.cookie('jwtUser', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

            res.json({ accessToken })
        }
    );
}

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken

    const cookies = req.cookies;
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
}

// private controllers
const handleGetProfile = async (req, res, next) => {
    try {
        const profile = await User.findOne({ email: req.email }).exec();
        if (!profile) return res.redirect('/user/logout');

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
        if (!profile) return res.redirect('/user/logout'); 
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
    if (!profile) return res.redirect('/user/logout'); 
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