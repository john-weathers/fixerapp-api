const express = require('express');
const verifyFixerJWT = require('../../middleware/verifyFixerJWT');
const verifyRoles = require('../../middleware/verifyRoles');
const ROLES = require('../../config/roles');
const { 
  handleGetProfile,
  handleUpdateProfile,
  handleUpdateSettings,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.use(verifyFixerJWT, verifyRoles(ROLES.fixer, ROLES.premiumFixer));
router.get('/profile', handleGetProfile);
router.patch('/update-profile', handleUpdateProfile);
router.patch('/update-settings', handleUpdateSettings);

const workRouter = require('./work');
router.use('/work', workRouter);

module.exports = router;