const express = require('express');
const {
  currentWork, 
  findWork,
  updateDirections,
  handleArrival,
  handleQuote,
  handleRevisedCost,
  handleComplete,
  handleRating,
} = require('../../controllers/fixers.controller');
const router = express.Router();

router.get('/current', currentWork);
router.post('/find', findWork);
router.patch('/directions', updateDirections);
router.patch('/arrival', handleArrival);
router.patch('/quote', handleQuote);
router.patch('/revise-cost', handleRevisedCost);
router.patch('/complete', handleComplete);
router.patch('/rate-client', handleRating);

module.exports = router;