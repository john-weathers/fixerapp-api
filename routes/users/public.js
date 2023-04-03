const express = require('express');
const router = express.Router();
const {
  handleRegistration,
  handleLogin,
  handleRefreshToken,
  handleLogout,
  cookieTest,
} = require('../../controllers/users.controller');

router.post('/register', handleRegistration);
router.post('/auth', handleLogin);
router.get('/refresh', handleRefreshToken);
router.get('/cookie-test', cookieTest);
router.route('/logout')
  .get(handleLogout)
  .post(handleLogout);

module.exports = router;