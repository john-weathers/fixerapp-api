const mongoose = require('mongoose');
const Fixer = require('../models/Fixer');
const User = require('../models/User');
const Request = require('../models/Request');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mbxDirections = require('@mapbox/mapbox-sdk/services/directions');
const MAPBOX_TOKEN = process.env.MAPBOX_TOKEN;
const directionsService = mbxDirections({ accessToken: MAPBOX_TOKEN });
const assert = require('assert');

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
    if (!PWD_REGEX.test(pwd)) return res.status(400).json({ 'message': 'Password invalid' });
    if (!email || !pwd || !firstName || !lastName || !phoneNumber) return res.status(400).json({ 'message': 'Please submit all required fields' });

    const trimmedEmail = email.trim()
    const duplicateUser = await Fixer.findOne({ email: trimmedEmail }).exec();
    if (duplicateUser) return res.sendStatus(409);

    const trimmedFirst = firstName.trim();
    const trimmedLast = lastName.trim();
    const trimmedPhone = phoneNumber.trim();

    try {
        const hashedPassword = await bcrypt.hash(pwd, 10);

        const result = await Fixer.create({
            email: trimmedEmail,
            password: hashedPassword,
            name: {
                first: trimmedFirst,
                last: trimmedLast,
            },
            phoneNumber: trimmedPhone,
        });

        res.status(201).json({ 'success': `New fixer at ${trimmedEmail} created!` });
    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
}

const handleLogin = async (req, res) => {
    const cookies = req.cookies;
    const { email, pwd } = req.body;
    if (!email || !pwd) return res.status(400).json({ 'message': 'Email and password are required for login.' });

    const foundUser = await Fixer.findOne({ email }).exec();
    if (!foundUser) return res.sendStatus(401);
    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {
        const roles = Object.values(foundUser.roles).filter(Boolean);
        const accessToken = jwt.sign(
            {
                'userInfo': {
                    'email': foundUser.email,
                    roles,
                },
            },
            process.env.FIXER_ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );
        const newRefreshToken = jwt.sign(
            { 'email': foundUser.email },
            process.env.FIXER_REFRESH_TOKEN_SECRET,
            { expiresIn: '8h' }
        );
        
        let newRefreshTokenArray =
            !cookies?.jwt
                ? foundUser.refreshToken
                : foundUser.refreshToken.filter(rt => rt !== cookies.jwt);

        if (cookies?.jwt) {

            const refreshToken = cookies.jwt;
            const foundToken = await Fixer.findOne({ refreshToken }).exec();

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
}

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;
    
    try {
        const foundUser = await Fixer.findOne({ refreshToken }).exec();
        if (!foundUser) {
            // added to deal with multiple rapid successive calls to handleRefreshToken
            // plan would be to add better deduplication on front end as a better long-term solution
            try {
                const refreshCheck = await Fixer.findOne({ 'prevTokens.refreshTokens': refreshToken }).exec();
                if (refreshCheck && new Date() - refreshCheck.prevTokens.lastRefresh < 1000) {
                    jwt.verify(
                        refreshToken,
                        process.env.FIXER_REFRESH_TOKEN_SECRET,
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
                        process.env.FIXER_REFRESH_TOKEN_SECRET,
                        async (err, decoded) => {
                            if (err) return res.sendStatus(403);
                            const hackedUser = await Fixer.findOne({ email: decoded.email }).exec();
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
            process.env.FIXER_REFRESH_TOKEN_SECRET,
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
                    process.env.FIXER_ACCESS_TOKEN_SECRET,
                    { expiresIn: '1h' }
                );
    
                const newRefreshToken = jwt.sign(
                    { 'email': foundUser.email },
                    process.env.FIXER_REFRESH_TOKEN_SECRET,
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

    const foundUser = await Fixer.findOne({ refreshToken }).exec();
    if (!foundUser) {
        // trying to mitigate scenario where a refresh fires just before logout
        // in this case, cookie could be stale and not match the most recently added RT in db
        try {
            const refreshCheck = await Fixer.findOne({ 'prevTokens.refreshTokens': refreshToken }).exec();
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
    const profile = await Fixer.findOne({ email: req.email }).exec();
    if (!profile) return res.sendStatus(401);

    const profileData = {
        email: profile.email,
        firstName: profile.name.first,
        lastName: profile.name.last,
        phoneNumber: profile.phoneNumber,
        rating: profile.rating,
        settings: profile.settings,
        premium: !!profile.roles.premiumFixer,
    }

    res.send(profileData);
}

const handleUpdateProfile = async (req, res, next) => {
    const { updateKey, updateData } = req.body;

    try {
        if (updateKey === 'email') {
            const newEmail = updateData?.updateData;
            const pwd = updateData?.pwd;
            const cookies = req.cookies;

            if (!newEmail || !pwd) return res.sendStatus(400);

            const foundUser = await Fixer.findOne({ email: req.email }).exec();
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
                    process.env.FIXER_ACCESS_TOKEN_SECRET,
                    { expiresIn: '1h' }
                );
                const newRefreshToken = jwt.sign(
                    { 'email': foundUser.email },
                    process.env.FIXER_REFRESH_TOKEN_SECRET,
                    { expiresIn: '8h' }
                );
                
                let newRefreshTokenArray =
                    !cookies?.jwt
                        ? foundUser.refreshToken
                        : foundUser.refreshToken.filter(rt => rt !== cookies.jwt);
        
                if (cookies?.jwt) {
        
                    const refreshToken = cookies.jwt;
                    const foundToken = await Fixer.findOne({ refreshToken }).exec();
        
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

            const foundUser = await Fixer.findOne({ email: req.email }).exec();
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

            const foundUser = await Fixer.findOne({ email: req.email }).exec();
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
        const foundUser = await Fixer.findOne({ email: req.email }).exec();
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

const currentWork = async (req, res, next) => {
    try {
        const profile = await Fixer.findOne({ email: req.email }).exec();
        if (!profile) return res.sendStatus(401);
        if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

        const activeJob = await Request.findOne({ fixer: profile._id, currentStatus: 'in progress' })
            .populate('user', 'name phoneNumber')
            .exec();

        if (!activeJob) return res.sendStatus(404);

        const quote = activeJob.get('quote');
        const workStartedAt = activeJob.get('workStartedAt');

        const jobDetails = {
            jobId: activeJob._id,
            userLocation: activeJob.userLocation.coordinates,
            fixerLocation: activeJob.fixerLocation.coordinates,
            userAddress: activeJob.userAddress,
            firstName: activeJob.user.name.first,
            lastName: activeJob.user.name.last,
            phoneNumber: activeJob.user.phoneNumber,
            currentStatus: activeJob.currentStatus,
            trackerStage: activeJob.trackerStage,
            assignedAt: activeJob.assignedAt,
            eta: activeJob.eta,
            route: activeJob.route,
            quote,
            workStartedAt, 
        }
        res.status(200).send(jobDetails);
    } catch (err) {
        res.status(500).send(err.message);
    }
}

const findWork = async (req, res, next) => {
    const { location } = req.body;
    if (!location?.length) return res.sendStatus(400);
    const geojsonPoint = { type: 'Point', coordinates: location } 

    const profile = await Fixer.findOne({ email: req.email }).exec();
    if (!profile) return res.sendStatus(401);
    if (!mongoose.isObjectIdOrHexString(profile._id)) return res.sendStatus(500);

    try {
        const activeRequests = await Request.aggregate([
            {
                $geoNear: {
                    near: geojsonPoint,
                    distanceField: 'distance',
                    maxDistance: profile.settings.extendedOptIn ? 64374 : 32187, // about 40 miles if opted in, 20 if not (default unit meters)
                    query: { 
                        active: true, // filter for active requests only
                        $expr: { $gt: [ '$requestedAt', { $dateSubtract: { startDate: '$$NOW', unit: 'minute', amount: 2 } } ] } // eliminate stale requests
                    },
                }
            },
            { $sort: { requestedAt: 1 } }, // older (non-stale) requests should be satisfied first
            { $limit: 10 }, // only one request will be matched, so we can limit to a pool of eligible candidates (can adjust number if needed).
        ]);

        if (!activeRequests?.length) return res.sendStatus(404);
        // loop through multiple candidates in the event that a request was matched after aggregation and before updateOne (thinking about a scenario with many requests in a busy area)
        for await (const activeRequest of activeRequests) {
            const session = await mongoose.startSession();
            try {
                session.startTransaction();
                if (activeRequest.distance > 32187 && !activeRequest.extendedOptIn) {
                    await session.abortTransaction();
                    session.endSession();
                    continue;
                }
                const assignedJob = await Request.findOneAndUpdate(
                    { _id: activeRequest._id, active: true },
                    { active: false, currentStatus: 'in progress', fixerLocation: geojsonPoint, trackerStage: 'en route', assignedAt: new Date(), fixer: profile._id },
                    { runValidators: true, session: session, new: true, context: 'query', previous: activeRequest.active } // make sure we're not dealing with a stale active value
                )
                    .populate('user', 'name phoneNumber')
                    .exec();

                if (!assignedJob) {
                    await session.abortTransaction();
                    session.endSession();
                    continue;
                } else {
                    await Fixer.updateOne({ email: req.email }, { activeJob: activeRequest._id }, { session: session });
                    
                    const response = await directionsService.getDirections({
                        profile: 'driving-traffic',
                        steps: true,
                        geometries: 'geojson',
                        waypoints: [
                            { coordinates: location },
                            { coordinates: assignedJob.userLocation.coordinates },
                        ]
                        })
                        .send();
                    const data = response.body;
                    const routeObject = data.routes[0];
            
                    assert.ok(assignedJob.$session())
                    assignedJob.route.coordinates = routeObject.geometry.coordinates;
                    assignedJob.route.instructions = routeObject.legs[0].steps.map(step => step.maneuver.instruction);
                    assignedJob.route.duration = routeObject.duration;
                    const addedTime = (routeObject.duration * 1000) + 180000;
                    assignedJob.eta = Date.now() + addedTime;
                    await assignedJob.save();

                    await session.commitTransaction();
                    
                    const jobDetails = {
                        jobId: assignedJob._id,
                        fixerLocation: assignedJob.fixerLocation.coordinates,
                        userLocation: assignedJob.userLocation.coordinates,
                        userAddress: assignedJob.userAddress,
                        firstName: assignedJob.user.name.first,
                        lastName: assignedJob.user.name.last,
                        phoneNumber: assignedJob.user.phoneNumber,
                        currentStatus: assignedJob.currentStatus,
                        trackerStage: assignedJob.trackerStage,
                        assignedAt: assignedJob.assignedAt,
                        route: assignedJob.route,
                        eta: assignedJob.eta, 
                    }

                    return res.status(201).send(jobDetails);
                }

            } catch (err) {
                await session.abortTransaction();
                session.endSession();
                continue; // if validation fails (or other error), move to next closest candidate
            }
        }
        res.sendStatus(404);
    } catch (err) {
        res.sendStatus(500);
    }

}

const updateDirections = async (req, res, next) => {
    const { jobId, location } = req.body;

    try {
        if (!mongoose.isObjectIdOrHexString(jobId)) return res.sendStatus(500);
        if (!location?.length) return res.sendStatus(400);

        const assignedJob = await Request.findOne({ _id: jobId, currentStatus: 'in progress' }).exec();
        if (!assignedJob?.userLocation?.coordinates?.length) return res.sendStatus(404);

        const response = await directionsService.getDirections({
            profile: 'driving-traffic',
            steps: true,
            geometries: 'geojson',
            waypoints: [
                { coordinates: location },
                { coordinates: assignedJob.userLocation.coordinates },
            ]
          })
            .send();
        const data = response.body;
        const routeObject = data.routes[0];

        assignedJob.route.coordinates = routeObject.geometry.coordinates;
        assignedJob.route.instructions = routeObject.legs[0].steps.map(step => step.maneuver.instruction);
        assignedJob.route.duration = routeObject.duration;
        const addedTime = (routeObject.duration * 1000) + 120000;
        assignedJob.eta = Date.now() + addedTime;
        await assignedJob.save();

        const jobDetails = {
            route: assignedJob.route,
            eta: assignedJob.eta,
        }

        res.status(200).send(jobDetails);
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleArrival = async (req, res, next) => {
    const { jobId } = req.body;
    try {
        const response = await Request.updateOne({ _id: jobId }, { trackerStage: 'arriving' });
        if (!response.modifiedCount) return res.sendStatus(404);
        res.sendStatus(200);
      } catch (err) {
        res.sendStatus(500);
      }
}

const handleQuote = async (req, res, next) => {
    const { quote, notes, jobId } = req.body;
    if (notes.length > 1000) return res.sendStatus(400);
    try {
        const request = await Request.findOne({ _id: jobId }).exec();
        if (!request) return res.sendStatus(404);
        const quoteInfo = {
            amount: quote,
            details: [...request?.quote?.details, notes],
            pending: true,
        }
        request.quote = quoteInfo;
        await request.save();
        res.sendStatus(200);
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleRevisedCost = async (req, res, next) => {
    const { revisedCost, notes, jobId } = req.body;
    if (notes.length > 500) return res.sendStatus(400);
    try {
        const request = await Request.findOne({ _id: jobId }).exec();
        if (!request?.quote?.amount) return res.sendStatus(404);
        const quoteInfo = {
            amount: revisedCost,
            details: [...request?.quote?.details, notes],
            revisedPending: true,
        }
        request.quote = quoteInfo;
        await request.save();
        res.sendStatus(200);
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleComplete = async (req, res, next) => {
    const { jobId, jobNotes } = req.body;
    try {
        if (!jobNotes) return res.sendStatus(400);
        const response = await Request.updateOne({ _id: jobId }, { trackerStage: 'complete', currentStatus: 'fulfilled', notes: jobNotes });
        if (!response.modifiedCount) return res.sendStatus(404);
        res.sendStatus(200);
    } catch (err) {
        res.sendStatus(500);
    }
}

const handleRating = async (req, res, next) => {
    const { jobId, rating } = req.body;
    if (!rating || !jobId || rating < 1 || rating > 5) return res.sendStatus(400);

    try {
        const { user } = await Request.findOne({ _id: jobId }).exec();
        if (!user) return res.sendStatus(404);

        const userRatings = await User.findOneAndUpdate(
            { _id: user }, 
            { $push: { ratings: rating } }, 
            { new: true }
        )
            .select('ratings');
        if (userRatings?.ratings?.length) {
            const rating = userRatings.ratings.reduce((a, cv) => a + cv) / userRatings.ratings.length;
            userRatings.rating = Number(rating.toFixed(2));
            await userRatings.save();
            res.sendStatus(200);
        } else {
            res.sendStatus(404);
        }
    } catch (err) {
        res.sendStatus(500);
    }
}

module.exports = {
    handleLogin,
    handleRegistration,
    handleRefreshToken,
    handleLogout,
    handleGetProfile,
    handleUpdateProfile,
    handleUpdateSettings,
    currentWork,
    findWork,
    updateDirections,
    handleArrival,
    handleQuote,
    handleRevisedCost,
    handleComplete,
    handleRating,
}