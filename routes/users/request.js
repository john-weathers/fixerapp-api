const express = require('express');
const { 
  currentRequest,
  handleQuoteDecision,
  handleRating,
} = require('../../controllers/users.controller');
const router = express.Router();

router.get('/current', currentRequest);
router.patch('/quote', handleQuoteDecision)
router.patch('/rate-fixer', handleRating)

module.exports = router;