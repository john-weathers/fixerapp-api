const express = require('express');
const verifyFixerJWT = require('../middleware/verifyFixerJWT');
const verifyRoles = require('../middleware/verifyRoles');
const ROLES = require('../config/roles');
const { 
  handleGetProfile,
} = require('../controllers/fixers.controller');
const router = express.Router();

router.all(verifyFixerJWT);
router.get('/profile', verifyRoles(ROLES.fixer, ROLES.premiumFixer), handleGetProfile);