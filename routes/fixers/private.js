const express = require('express');
const verifyFixerJWT = require('../../middleware/verifyFixerJWT');
const verifyRoles = require('../../middleware/verifyRoles');
const ROLES = require('../../config/roles');
const { 
  handleGetProfile,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.all(verifyFixerJWT, verifyRoles(ROLES.fixer, ROLES.premiumFixer));
router.get('/profile', handleGetProfile);

module.exports = router;