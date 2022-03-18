const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { validateRegisterInput, validateLoginInput } = require('../../utils/validators')
const User = require('../../models/User.js')
const { SECRET_KEY } = require('../../config');
const { UserInputError } = require('apollo-server-errors');

const generateToken = (user) =>
    jwt.sign({
        id: user.id,
        email: user.email,
        username: user.username
    }, SECRET_KEY, { expiresIn: '1h' })


module.exports = {
    Mutation: {
        async register(
            _,
            { registerInput: { username, email, password, confirmPassword } }
        ) {
            //Validate user data
            const { valid, errors } = validateRegisterInput(username, email, password, confirmPassword);
            if (!valid) {
                throw new UserInputError('Register Input Errors', { errors })
            }

            // Make sure user doesnt exist already
            const user = await User.findOne({ username })
            if (user) {
                throw new UserInputError('Username is taken', {
                    errors: {
                        username: 'This username is taken'
                    }
                })
            }

            // Hash password and create an auth token
            password = await bcrypt.hash(password, 12);

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            })

            const res = await newUser.save();

            const token = generateToken(res);

            return {
                ...res._doc,
                id: res._id,
                token
            }
        },
        async login(_, { username, password }) {
            //Validate user data
            const { valid, errors } = validateLoginInput(username, password);
            if (!valid) {
                throw new UserInputError('Login Input Errors', { errors })
            }

            const user = await User.findOne({ username })
            if (!user) {
                errors.general = 'User not found'
                throw new UserInputError('User not found', { errors })
            }

            const isMatching = await bcrypt.compare(password, user.password)
            if (!isMatching) {
                errors.general = 'Wrong Credentials'
                throw new UserInputError('Wrong Password', { errors })
            }

            const token = generateToken(user);

            return {
                ...user._doc,
                id: user._id,
                token
            }
        }

    }
}