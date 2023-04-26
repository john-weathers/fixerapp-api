const express = require('express');
const { 
  currentRequest,
  handleQuoteDecision,
  handleRevisedQuote,
  handleRating,
} = require('../../controllers/users.controller');
const router = express.Router();

router.get('/current', currentRequest);
router.patch('/quote', handleQuoteDecision);
router.patch('/revised-quote', handleRevisedQuote);
router.patch('/rate-fixer', handleRating);

module.exports = router;