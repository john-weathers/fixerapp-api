const express = require('express');
const verifyUserJWT = require('../middleware/verifyUserJWT');
const verifyRoles = require('../middleware/verifyRoles');
const ROLES = require('../config/roles');
const { 
  handleGetProfile,
} = require('../controllers/users.controller');
const router = express.Router();

router.all(verifyUserJWT);
router.get('/profile', verifyRoles(ROLES.user, ROLES.premiumUser), handleGetProfile);