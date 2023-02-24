const express = require('express');
const verifyUserJWT = require('../../middleware/verifyUserJWT');
const verifyRoles = require('../../middleware/verifyRoles');
const ROLES = require('../../config/roles');
const { 
  handleGetProfile,
} = require('../../controllers/users.controller');
const router = express.Router();

router.use(verifyUserJWT, verifyRoles(ROLES.user, ROLES.premiumUser));
router.get('/profile', handleGetProfile);

const requestRouter = require('./request');
router.use('/request', requestRouter);

module.exports = router;