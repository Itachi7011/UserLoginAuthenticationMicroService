const express = require('express');
const passport = require('passport');
const { body, validationResult } = require('express-validator');
const Client = require('../models/Client');
const Token = require('../models/ClientToken');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Generate JWT token for client
const generateClientToken = (client) => {
    return jwt.sign(
        {
            clientId: client._id,
            apiKey: client.apiKey
        },
        process.env.JWT_SECRET || 'your_jwt_secret',
        { expiresIn: '24h' }
    );
};

// Generate API key
const generateApiKey = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Client registration
router.post('/register', [
    body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('website').isURL().withMessage('Please provide a valid website URL'),
    body('description').optional().trim()
], async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { name, email, password, website, description } = req.body;

        // Check if client already exists
        const existingClient = await Client.findOne({
            $or: [{ email }, { website }],
            isDeleted: false
        });

        if (existingClient) {
            return res.status(409).json({
                status: 'error',
                message: 'Client with this email or website already exists'
            });
        }

        // Generate API key
        const apiKey = generateApiKey();
        const secretKey = crypto.randomBytes(16).toString('hex');

        // Create new client
        const client = new Client({
            name,
            email,
            password,
            website,
            description,
            apiKey,
            secretKey
        });

        await client.save();

        // Generate JWT token
        const token = generateClientToken(client);

        res.status(201).json({
            status: 'success',
            message: 'Client registered successfully',
            data: {
                client: {
                    id: client._id,
                    name: client.name,
                    email: client.email,
                    website: client.website,
                    apiKey: client.apiKey
                },
                token
            }
        });
    } catch (error) {
        next(error);
    }
});

// Client login with email/password
router.post('/login', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { email, password } = req.body;

        // Find client by email
        const client = await Client.findOne({
            email,
            isActive: true,
            isDeleted: false
        });

        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        // Check if account is locked
        if (client.isLocked) {
            return res.status(401).json({
                status: 'error',
                message: 'Account is temporarily locked due to too many failed login attempts'
            });
        }

        // Check password
        const isPasswordValid = await client.comparePassword(password);

        if (!isPasswordValid) {
            // Increment login attempts
            await client.incrementLoginAttempts();

            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        console.log(client)

        // Reset login attempts on successful login
        await Client.findByIdAndUpdate(client._id, {
            loginAttempts: 0,
            lockUntil: null,
            lastLogin: new Date()
        });

        // Generate JWT token
        const token = generateClientToken(client);

        res.json({
            status: 'success',
            message: 'Client authenticated successfully',
            data: {
                client: {
                    id: client._id,
                    name: client.name,
                    email: client.email,
                    website: client.website,
                    apiKey: client.apiKey,
                    subscription: client.subscription
                },
                token
            }
        });
    } catch (error) {
        next(error);
    }
});

// Google OAuth for clients
router.get('/google',
    passport.authenticate('client-google', {
        scope: ['profile', 'email'],
        session: false
    })
);

router.get('/google/callback',
    passport.authenticate('client-google', {
        failureRedirect: '/client-login?error=auth_failed',
        session: false
    }),
    async (req, res) => {
        try {
            // Generate JWT token
            const token = generateClientToken(req.user);

            // Redirect to CLIENT-SIDE dashboard with token in URL params
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-dashboard?token=${token}&clientId=${req.user._id}`);
        } catch (error) {
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-login?error=token_generation_failed`);
        }
    }
);

// GitHub OAuth for clients
router.get('/github',
    passport.authenticate('client-github', {
        scope: ['user:email'],
        session: false
    })
);

router.get('/github/callback',
    passport.authenticate('client-github', {
        failureRedirect: '/client-login?error=auth_failed',
        session: false
    }),
    async (req, res) => {
        try {
            const token = generateClientToken(req.user);
            // Redirect to CLIENT-SIDE
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-dashboard?token=${token}&clientId=${req.user._id}`);
        } catch (error) {
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-login?error=token_generation_failed`);
        }
    }
);


// Get client profile (protected route)
router.get('/profile', async (req, res, next) => {
    try {
        // Extract client ID from token (you'll need middleware for this)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required'
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');

        const client = await Client.findById(decoded.clientId).select('-password -__v');

        if (!client) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        res.json({
            status: 'success',
            data: { client }
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router;