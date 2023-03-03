const express = require('express');
const {
  currentWork, 
  findWork,
  cancelWork,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.get('/current', currentWork);
router.post('/find', findWork);
router.post('/cancel', cancelWork);

module.exports = router;