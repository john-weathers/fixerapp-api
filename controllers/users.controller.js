const User = require('../models/User');
const Fixer = require('../models/Fixer');
const Request = require('../models/Request');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const COOKIE_AGE = 24 * 60 * 60 * 1000;

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

    const trimmedEmail = email.trim()
    const duplicateUser = await User.findOne({ email: trimmedEmail }).exec();
    if (duplicateUser) return res.sendStatus(409);

    const trimmedFirst = firstName.trim();
    const trimmedLast = lastName.trim();
    const trimmedPhone = phoneNumber.trim();

    try {
        const hashedPassword = await bcrypt.hash(pwd, 10);
        
        const result = await User.create({
            email: trimmedEmail,
            password: hashedPassword,
            name: {
                first: trimmedFirst,
                last: trimmedLast,
            },
            phoneNumber: trimmedPhone,
        });

        res.status(201).json({ 'success': `New user at ${trimmedEmail} created!` });
    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
}

const handleLogin = async (req, res) => {
    const cookies = req.cookies;
    const { email, pwd } = req.body;
    if (!email || !pwd) return res.status(400).json({ 'message': 'Email and password are required for login.' });

    const foundUser = await User.findOne({ email }).exec();
    if (!foundUser) return res.sendStatus(401);
    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {
        const roles = Object.values(foundUser.roles).filter(Boolean);
        const accessToken = jwt.sign(
            {
                'userInfo': {
                    'email': foundUser.email,
                    'roles': roles,
                },
            },
            process.env.USER_ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );
        const newRefreshToken = jwt.sign(
            { 'email': foundUser.email },
            process.env.USER_REFRESH_TOKEN_SECRET,
            { expiresIn: '8h' }
        );
        
        let newRefreshTokenArray =
            !cookies?.jwt
                ? foundUser.refreshToken
                : foundUser.refreshToken.filter(rt => rt !== cookies.jwt);

        if (cookies?.jwt) {

            const refreshToken = cookies.jwt;
            const foundToken = await User.findOne({ refreshToken }).exec();

            if (!foundToken) {
                newRefreshTokenArray = [];
            }

            res.clearCookie('jwt', { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
        }
        
        foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
        foundUser.prevTokens.refreshTokens = [];
        await foundUser.save();

        res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, maxAge: COOKIE_AGE });

        res.status(200).send({ accessToken });

    } else {
        res.sendStatus(401);
    }
}

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;
    
    try {
        const foundUser = await User.findOne({ refreshToken }).exec();
        if (!foundUser) {
            // added to deal with multiple rapid successive calls to handleRefreshToken
            // plan would be to add better deduplication on front end as a better long-term solution
            try {
                const refreshCheck = await User.findOne({ 'prevTokens.refreshTokens': refreshToken }).exec();
                if (refreshCheck && new Date() - refreshCheck.prevTokens.lastRefresh < 1000) {
                    jwt.verify(
                        refreshToken,
                        process.env.USER_REFRESH_TOKEN_SECRET,
                        async (err, decoded) => {
                            if (err) {
                                return res.sendStatus(403);
                            }
                            const prevTokenDetails = {
                                accessToken: refreshCheck.prevTokens.accessToken
                            }
                            const prevArr = refreshCheck.prevTokens.refreshTokens;
                            const refreshArrLength = prevArr.length;
                            if (refreshArrLength > 10) {
                                refreshCheck.prevTokens.refreshTokens.pop();
                                await refreshCheck.save();
                            }
                            if (res.headersSent) return;
                            return res.send(prevTokenDetails);
                                
                        }
                    );
                    if (res.headersSent) return;
                    res.sendStatus(403);
                } else {
                    res.clearCookie('jwt', { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
                    jwt.verify(
                        refreshToken,
                        process.env.USER_REFRESH_TOKEN_SECRET,
                        async (err, decoded) => {
                            if (err) return res.sendStatus(403);
                            const hackedUser = await User.findOne({ email: decoded.email }).exec();
                            hackedUser.refreshToken = [];
                            const result = await hackedUser.save();
                        }
                    );
                    if (res.headersSent) return;
                    res.sendStatus(403);
                }
            } catch (err) {
                // console.log(err.message);
            }
        }
        if (res.headersSent) return;
        res.clearCookie('jwt', { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
        
        const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken);
    
        jwt.verify(
            refreshToken,
            process.env.USER_REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) {
                    foundUser.refreshToken = [...newRefreshTokenArray];
                    const result = await foundUser.save();
                }
                if (err || foundUser.email !== decoded.email) return res.sendStatus(403);
    
                const roles = Object.values(foundUser.roles);
                const accessToken = jwt.sign(
                    {
                        'userInfo': {
                            'email': decoded.email,
                            'roles': roles,
                        },
                    },
                    process.env.USER_ACCESS_TOKEN_SECRET,
                    { expiresIn: '1h' }
                );
    
                const newRefreshToken = jwt.sign(
                    { 'email': foundUser.email },
                    process.env.USER_REFRESH_TOKEN_SECRET,
                    { expiresIn: '8h' }
                );
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
    
                res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
    
                return res.status(200).send({ accessToken });
            }
        );
    } catch (err) {
        if (res.headersSent) return;
        res.sendStatus(500);
    }
    
  }

const handleLogout = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204);
    const refreshToken = cookies.jwt;

    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) {
        // trying to mitigate scenario where a refresh fires just before logout
        // in this case, cookie could be stale and not match the most recently added RT in db
        try {
            const refreshCheck = await User.findOne({ 'prevTokens.refreshTokens': refreshToken }).exec();
            // if the cookie RT matches a previous RT, and a refresh has happened within the last second, we remove the last RT in db
            if (refreshCheck && new Date() - refreshCheck.prevTokens.lastRefresh < 1000) {
                refreshCheck.refreshToken.pop();
                refreshCheck.prevTokens.refreshTokens = [];
                await refreshCheck.save();
            }
        } catch (err) {
            // console.log(err.message);
        }
        // cookie is cleared either way
        res.clearCookie('jwt', { httpOnly: true, secure: true, maxAge: COOKIE_AGE }); // revisit clearCookie options
        return res.sendStatus(204);
    }
    // Delete refreshToken in db
    foundUser.refreshToken = foundUser.refreshToken.filter(rt => rt !== refreshToken);;
    foundUser.prevTokens.refreshTokens = [];
    const result = await foundUser.save();

    res.clearCookie('jwt', { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
    res.sendStatus(204);
}

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
            settings: profile.settings,
            premium: !!profile.roles.premiumUser,
        }
        res.send(profileData);
    } catch (err) {
        res.status(500).send(err.message);
    }
}

const handleUpdateProfile = async (req, res, next) => {
    const { updateKey, updateData } = req.body;

    try {
        if (updateKey === 'email') {
            const newEmail = updateData?.updateData;
            const pwd = updateData?.pwd;
            const cookies = req.cookies;

            if (!newEmail || !pwd) return res.sendStatus(400);

            const foundUser = await User.findOne({ email: req.email }).exec();
            if (!foundUser) return res.sendStatus(401);

            const match = await bcrypt.compare(pwd, foundUser.password);
            if (match) {
                const roles = Object.values(foundUser.roles).filter(Boolean);
                foundUser.email = newEmail;
                await foundUser.save();
                const accessToken = jwt.sign(
                    {
                        'userInfo': {
                            'email': foundUser.email,
                            roles,
                        },
                    },
                    process.env.USER_ACCESS_TOKEN_SECRET,
                    { expiresIn: '1h' }
                );
                const newRefreshToken = jwt.sign(
                    { 'email': foundUser.email },
                    process.env.USER_REFRESH_TOKEN_SECRET,
                    { expiresIn: '8h' }
                );
                
                let newRefreshTokenArray =
                    !cookies?.jwt
                        ? foundUser.refreshToken
                        : foundUser.refreshToken.filter(rt => rt !== cookies.jwt);
        
                if (cookies?.jwt) {
        
                    const refreshToken = cookies.jwt;
                    const foundToken = await User.findOne({ refreshToken }).exec();
        
                    if (!foundToken) {
                        newRefreshTokenArray = [];
                    }
        
                    res.clearCookie('jwt', { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
                }
        
                foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
                await foundUser.save();
        
                res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, maxAge: COOKIE_AGE });
        
                res.status(200).send({ accessToken });
            
            } else {
                res.sendStatus(401);
            }
        } else if (updateKey === 'password') {
            const oldPwd = updateData?.oldPwd;
            const newPwd = updateData?.newPwd;
            const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/;

            if (!oldPwd || !newPwd || !PWD_REGEX.test(newPwd)) return res.sendStatus(400);

            const foundUser = await User.findOne({ email: req.email }).exec();
            if (!foundUser) return res.sendStatus(401);

            const match = await bcrypt.compare(oldPwd, foundUser.password);

            if (match) {
                const newHashedPassword = await bcrypt.hash(newPwd, 10);
                foundUser.password = newHashedPassword;
                await foundUser.save();
                res.sendStatus(200);
            } else {
                res.sendStatus(401);
            }
        } else {
            const change = updateData?.updateData;
            const pwd = updateData?.pwd;

            if (!change || !pwd) return res.sendStatus(400);

            const foundUser = await User.findOne({ email: req.email }).exec();
            if (!foundUser) return res.sendStatus(401);

            const match = await bcrypt.compare(pwd, foundUser.password);

            if (match) {
                if (updateKey === 'phoneNumber') {
                    foundUser[updateKey] = change;
                } else {
                    foundUser.name[updateKey] = change;
                }
                await foundUser.save();
                res.sendStatus(200);
            } else {
                res.sendStatus(401);
            }
        }
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleUpdateSettings = async (req, res, next) => {
    const { updateKey } = req.body;
    if (!updateKey) return res.sendStatus(400);

    try {
        const foundUser = await User.findOne({ email: req.email }).exec();
        if (!foundUser) return res.sendStatus(401);

        if (Object.hasOwn(foundUser.settings, updateKey)) {
            foundUser.settings[updateKey] = !foundUser.settings[updateKey];
            await foundUser.save();
    
            res.sendStatus(200);
        } else {
            res.sendStatus(400);
        }
       
    } catch (err) {
        res.sendStatus(500);
    }
}

// replaced with websocket functionality
const fixRequest = async (req, res, next) => {
    const { location, address } = req.body;
    let responseSent = false;
    if (!location.length || !address) return res.sendStatus(400);

    try {
        const profile = await User.findOne({ email: req.email }).exec();
        if (!profile) return res.sendStatus(401); 
        if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

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
                eta: change.fullDocument?.route?.duration,
            }
            res.status(200).send(jobDetails);
            responseSent = true;
        });

        const closeChangeStream = () => {
            return new Promise((resolve) => {
                setTimeout(async () => {
                    const currentRequest = await Request.findOne({ user: profile._id, active: true });
                    if (!responseSent && newRequest.requestedAt === currentRequest?.requestedAt) res.sendStatus(408);
                    changeStream.close();
                    resolve();
                }, 120000);
            });
        }

        await closeChangeStream();
    } catch (err) {
        res.status(500).send(err.message);
    }
}

const currentRequest = async (req, res, next) => {
    try {
        const profile = await User.findOne({ email: req.email }).exec();
        if (!profile) return res.sendStatus(401);
        if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

        const activeJob = await Request.findOne({ user: profile._id, currentStatus: 'in progress' })
            .populate('fixer', 'name phoneNumber rating')
            .exec();

        if (!activeJob) return res.sendStatus(404);
        
        const fixer = activeJob.fixer.toObject();
        const quote = activeJob.get('quote');

        const jobDetails = {
            jobId: activeJob._id,
            userLocation: activeJob.userLocation.coordinates,
            userAddress: activeJob.userAddress,
            fixerLocation: activeJob.fixerLocation.coordinates,
            currentStatus: activeJob.currentStatus,
            assignedAt: activeJob.assignedAt,
            trackerStage: activeJob.trackerStage,
            fixerName: activeJob.fixer.name.first,
            fixerRating: fixer?.rating,
            phoneNumber: activeJob.fixer.phoneNumber,
            eta: activeJob.eta,
            quote,
        }

        res.status(200).send(jobDetails);
    } catch (err) {
        res.status(500).send(err.message);
    }

}

// replaced with websocket functionality
const cancelRequest = async (req, res, next) => {
    const profile = await User.findOne({ email: req.email }).exec();
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

const handleRevisedQuote = async (req, res, next) => {
    const { accept, jobId } = req.body;
    try {
        const request = await Request.findOne({ _id: jobId }).exec();
        if (!request) return res.sendStatus(404);

        if (accept) {
            request.quote.revisedAccepted = true;
        } else {
            request.quote.revisedAccepted = false;
        }
        request.quote.revisedPending = false;

        await request.save();
        res.sendStatus(200);
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleRating = async (req, res, next) => {
    const { jobId, rating } = req.body;
    if (!rating || !jobId || rating < 1 || rating > 5) return res.sendStatus(400);

    try {
        const { fixer } = await Request.findOne({ _id: jobId }).exec();
        if (!fixer) return res.sendStatus(404);

        const fixerRatings = await Fixer.findOneAndUpdate(
            { _id: fixer }, 
            { $push: { ratings: rating } }, 
            { new: true }
        )
            .select('ratings');
        if (fixerRatings?.ratings?.length) {
            const rating = fixerRatings.ratings.reduce((a, cv) => a + cv) / fixerRatings.ratings.length;
            fixerRatings.rating = Number(rating.toFixed(2));
            await fixerRatings.save();
            res.sendStatus(200);
        } else {
            res.sendStatus(404);
        }
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
    handleUpdateProfile,
    handleUpdateSettings,
    fixRequest,
    currentRequest,
    cancelRequest,
    handleQuoteDecision,
    handleRevisedQuote,
    handleRating,
}