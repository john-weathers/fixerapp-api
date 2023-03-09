const express = require('express');
const {
  currentWork, 
  findWork,
  updateDirections,
  cancelJob,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.get('/current', currentWork);
router.post('/find', findWork);
router.patch('/directions', updateDirections);
router.post('/cancel', cancelJob);

module.exports = router;