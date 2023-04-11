const express = require('express');
const router = express.Router();
const {
  handleRegistration,
  handleLogin,
  handleRefreshToken,
  handleLogout,
} = require('../../controllers/users.controller');

router.post('/register', handleRegistration);
router.post('/auth', handleLogin);
router.get('/refresh', handleRefreshToken);
router.get('/logout', handleLogout);

module.exports = router;