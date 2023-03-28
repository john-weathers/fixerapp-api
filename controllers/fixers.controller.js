const mongoose = require('mongoose');
const Fixer = require('../models/Fixer');
const Request = require('../models/Request');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mbxDirections = require('@mapbox/mapbox-sdk/services/directions');
const circle = require('@turf/circle').default;
const booleanPointInPolygon = require('@turf/boolean-point-in-polygon').default;
const MAPBOX_TOKEN = process.env.MAPBOX_TOKEN;
const directionsService = mbxDirections({ accessToken: MAPBOX_TOKEN });
const assert = require('assert');

// TODO: need to update all previous location properties for Request queries and any fixer location properties (which will now live on Request model)

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
    try {
        const { activeJob } = await Fixer.findOne({ email: req.email })
            .select('activeJob')
            .populate({
                path: 'activeJob',
                select: 'user location currentStatus trackerStage',
                populate: { path: 'user', select: 'name phoneNumber' },
            })
            .exec();
        if (activeJob?.currentStatus !== 'in progress') return res.sendStatus(404);
        const jobDetails = {
            userLocation: activeJob.location.coordinates,
            userAddress: activeJob.userAddress,
            firstName: activeJob.user.name.first,
            lastName: activeJob.user.name.last,
            phoneNumber: activeJob.user.phoneNumber,
            currentStatus: activeJob.currentStatus,
            trackerStage: activeJob.trackerStage,
            assignedAt: activeJob.assignedAt,
            route: activeJob.route, 
        }
        res.status(200).send(jobDetails);
    } catch (err) {
        res.status(500).send(err.message);
    }
}

const findWork = async (req, res, next) => {
    const { location } = req.body;
    if (!location.length) return res.sendStatus(400);
    const geojsonPoint = { type: 'Point', coordinates: location } 

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
        // NOTE: consider making this a transaction to ensure data is consistent between multiple related operations
        for await (const activeRequest of activeRequests) {
            const session = await mongoose.startSession();
            try {
                session.startTransaction();
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
                    /*profile.$session(session) // test to double check that this works (shouldn't be a problem)
                    // for now passing session to updateOne is fine
                    profile.activeJob = activeRequest._id;
                    await profile.save();*/ 

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
                    // not sure if each of these counts as a separate updateOne under the hood
                    // if so, it could be better to combine into one update operation depending on how the final watcher function pipeline is constructed
                    assignedJob.route.coordinates = routeObject.geometry.coordinates;
                    assignedJob.route.instructions = routeObject.legs[0].steps.map(step => step.maneuver.instruction);
                    assignedJob.route.duration = routeObject.duration;
                    const addedTime = (routeObject.duration * 1000) + 180000;
                    assignedJob.eta = new Date(dateTime.getTime() + addedTime); // NOTE: need to fix this and any other similar calculations with date
                    // this will not evaluate as expected
                    // try (e.g.): new Date(dateTime.getTime() + (5 * 60000))
                    await assignedJob.save();

                    /*const routeData = {
                        coordinates: routeObject.geometry.coordinates,
                        instructions: routeObject.legs[0].steps.map(step => step.maneuver.instruction),
                        duration: routeObject.duration,
                    }
                    const addedTime = (routeObject.duration * 1000) + 180000;
                    const eta = new Date(dateTime.getTime() + addedTime)

                    const jobDetailsFull = await Request.updateOne({  }) create single call to update one depending on how assignment updates work under the hood
                    see above comment for details
                    */

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
        if (!location.length) return res.sendStatus(400);

        const assignedJob = Request.findOne({ _id: jobId, currentStatus: 'in progress' }).exec();
        if (!assignedJob.userLocation.coordinates.length) return res.sendStatus(404);

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
        assignedJob.eta = new Date(dateTime.getTime() + addedTime)
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
            pending: true,
        }
        request.quote = quoteInfo;
        await request.save();
        res.sendStatus(200);
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
    currentWork,
    findWork,
    updateDirections,
    handleArrival,
    handleQuote,
    handleRevisedCost,
}