const User = require('../models/User');
const Fixer = require('../models/Fixer');
const bcrypt = require('bcrypt');

const handleRegistration = async (req, res) => {
    const { email, pwd, userType } = req.body;
    let database;
    if (!email || !pwd) return res.status(400).json({ 'message': 'Email and password are required for registration.' });

    // check for duplicate usernames in the db
    if (userType === 'user') {
        database = User;
    } else if (userType === 'fixer') {
        database = Fixer;
    } else {
        res.status(400).json({ 'message': 'User type must be specified.' })
    }

    const duplicateUser = await database.findOne({ email }).exec();

    if (duplicateUser) return res.sendStatus(409); //Conflict 

    try {
        //encrypt the password
        const hashedPassword = await bcrypt.hash(pwd, 10);

        //create and store the new user
        const result = await database.create({
            email,
            password: hashedPassword,
        });

        console.log(result);

        res.status(201).json({ 'success': `New ${userType} at ${email} created!` });
    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
}

module.exports = { handleRegistration };