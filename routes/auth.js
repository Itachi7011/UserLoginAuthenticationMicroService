// routes/auth.js
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const User = require('../models/User');
const Client = require('../models/Client');
const OTP = require('../models/OTP');
const Token = require('../models/Token');
const rabbitMQService = require('../services/rabbitmq');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// Configure passport for social logins
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ 'socialLogin.google.id': profile.id });

        if (user) {
            return done(null, user);
        }

        // Check if user exists with this email
        user = await User.findOne({ email: profile.emails[0].value });

        if (user) {
            // Link Google account to existing user
            user.socialLogin.google = {
                id: profile.id,
                token: accessToken
            };
            await user.save();
            return done(null, user);
        }

        // Create new user
        user = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            emailVerified: true,
            socialLogin: {
                google: {
                    id: profile.id,
                    token: accessToken
                }
            }
        });

        await user.save();
        done(null, user);
    } catch (error) {
        done(error, null);
    }
}));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "/api/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ 'socialLogin.github.id': profile.id });

        if (user) {
            return done(null, user);
        }

        // Check if user exists with this email (GitHub might not provide email)
        if (profile.emails && profile.emails[0]) {
            user = await User.findOne({ email: profile.emails[0].value });

            if (user) {
                // Link GitHub account to existing user
                user.socialLogin.github = {
                    id: profile.id,
                    token: accessToken
                };
                await user.save();
                return done(null, user);
            }
        }

        // Create new user
        user = new User({
            name: profile.displayName || profile.username,
            email: profile.emails ? profile.emails[0].value : `${profile.username}@github.user`,
            emailVerified: !!profile.emails,
            socialLogin: {
                github: {
                    id: profile.id,
                    token: accessToken
                }
            }
        });

        await user.save();
        done(null, user);
    } catch (error) {
        done(error, null);
    }
}));

// Register new user
router.post('/auth/register', [
    body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('clientApiKey').notEmpty().withMessage('Client API key is required')
], async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { name, email, password, clientApiKey } = req.body;

        // Verify client API key
        const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid client API key'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                status: 'error',
                message: 'User already exists with this email'
            });
        }

        // Create user
        const user = new User({
            name,
            email,
            password,
            clientId: client._id
        });

        await user.save();

        // Generate email verification OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + client.otpTemplate.expiration * 60 * 1000);

        await OTP.create({
            email: user.email,
            otp,
            type: 'email_verification',
            clientId: client._id,
            expiresAt
        });

        // Send OTP via email using RabbitMQ
        const emailData = {
            to: user.email,
            subject: client.otpTemplate.subject || 'Verify Your Email',
            template: 'otp',
            context: {
                name: user.name,
                otp,
                website: client.website,
                company: client.name,
                expiration: client.otpTemplate.expiration
            }
        };

        rabbitMQService.sendToQueue('email_queue', emailData);

        // Create audit log
        const auditLog = {
            action: 'user_registered',
            userId: user._id,
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.status(201).json({
            status: 'success',
            message: 'User registered successfully. Please verify your email.',
            data: {
                userId: user._id,
                email: user.email
            }
        });
    } catch (error) {
        next(error);
    }
});

// Login user
router.post('/login', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
    body('clientApiKey').notEmpty().withMessage('Client API key is required')
], async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { email, password, clientApiKey } = req.body;

        // Verify client API key
        const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid client API key'
            });
        }

        // Find user
        const user = await User.findOne({ email, clientId: client._id });
        if (!user || user.isBlocked) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid credentials or account blocked'
            });
        }

        // Check if account is locked
        if (user.isLocked) {
            return res.status(423).json({
                status: 'error',
                message: 'Account is temporarily locked due to too many failed login attempts'
            });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            // Increment login attempts
            await user.incrementLoginAttempts();

            // Create audit log
            const auditLog = {
                action: 'login_failed',
                userId: user._id,
                clientId: client._id,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                status: 'failure',
                metadata: { reason: 'Invalid password' }
            };

            rabbitMQService.sendToQueue('audit_log_queue', auditLog);

            return res.status(401).json({
                status: 'error',
                message: 'Invalid credentials'
            });
        }

        // Check if email is verified
        if (!user.emailVerified) {
            return res.status(403).json({
                status: 'error',
                message: 'Email not verified. Please verify your email first.'
            });
        }

        // Reset login attempts on successful login
        await User.updateOne(
            { _id: user._id },
            { $set: { loginAttempts: 0 }, $unset: { lockUntil: 1 }, lastLogin: new Date() }
        );

        // Generate tokens
        const accessToken = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
        );

        const refreshToken = jwt.sign(
            { userId: user._id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
        );

        // Save refresh token
        await Token.create({
            token: refreshToken,
            userId: user._id,
            type: 'refresh',
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            clientId: client._id
        });

        // Create audit log
        const auditLog = {
            action: 'login_success',
            userId: user._id,
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        // Update API metrics
        const metricsData = {
            clientId: client._id,
            userId: user._id,
            endpoint: '/api/auth/login',
            timestamp: new Date()
        };

        rabbitMQService.sendToQueue('api_metrics_queue', metricsData);

        res.json({
            status: 'success',
            message: 'Login successful',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                tokens: {
                    accessToken,
                    refreshToken
                }
            }
        });
    } catch (error) {
        next(error);
    }
});

// Verify email with OTP
router.post('/verify-email', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
    body('clientApiKey').notEmpty().withMessage('Client API key is required')
], async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { email, otp, clientApiKey } = req.body;

        // Verify client API key
        const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid client API key'
            });
        }

        // Find user
        const user = await User.findOne({ email, clientId: client._id });
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        if (user.emailVerified) {
            return res.status(400).json({
                status: 'error',
                message: 'Email already verified'
            });
        }

        // Find valid OTP
        const validOTP = await OTP.findOne({
            email,
            otp,
            type: 'email_verification',
            clientId: client._id,
            used: false,
            expiresAt: { $gt: new Date() }
        });

        if (!validOTP) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid or expired OTP'
            });
        }

        // Mark OTP as used and verify email
        await Promise.all([
            OTP.updateOne({ _id: validOTP._id }, { used: true }),
            User.updateOne({ _id: user._id }, { emailVerified: true, dateOfEmailValidation: new Date() })
        ]);

        // Create audit log
        const auditLog = {
            action: 'email_verified',
            userId: user._id,
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Email verified successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Resend OTP
router.post('/resend-otp', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('type').isIn(['email_verification', 'password_reset', '2fa']).withMessage('Invalid OTP type'),
    body('clientApiKey').notEmpty().withMessage('Client API key is required')
], async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { email, type, clientApiKey } = req.body;

        // Verify client API key
        const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid client API key'
            });
        }

        // Find user
        const user = await User.findOne({ email, clientId: client._id });
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Check if email is already verified for verification OTPs
        if (type === 'email_verification' && user.emailVerified) {
            return res.status(400).json({
                status: 'error',
                message: 'Email already verified'
            });
        }

        // Generate new OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + client.otpTemplate.expiration * 60 * 1000);

        // Invalidate previous OTPs of same type
        await OTP.updateMany(
            { email, type, clientId: client._id, used: false },
            { used: true }
        );

        // Save new OTP
        await OTP.create({
            email,
            otp,
            type,
            clientId: client._id,
            expiresAt
        });

        // Send OTP via email using RabbitMQ
        const emailData = {
            to: email,
            subject: type === 'password_reset'
                ? 'Password Reset Request'
                : client.otpTemplate.subject || 'Your Verification Code',
            template: 'otp',
            context: {
                name: user.name,
                otp,
                website: client.website,
                company: client.name,
                expiration: client.otpTemplate.expiration,
                purpose: type === 'password_reset' ? 'password reset' : 'verification'
            }
        };

        rabbitMQService.sendToQueue('email_queue', emailData);

        // Create audit log
        const auditLog = {
            action: 'otp_resent',
            userId: user._id,
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { type }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'OTP sent successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Google OAuth routes
router.get('/google', (req, res, next) => {
    const { clientApiKey, redirectUri } = req.query;

    if (!clientApiKey || !redirectUri) {
        return res.status(400).json({
            status: 'error',
            message: 'clientApiKey and redirectUri are required'
        });
    }

    // Store clientApiKey and redirectUri in session for callback
    req.session.clientApiKey = clientApiKey;
    req.session.redirectUri = redirectUri;

    passport.authenticate('google', {
        scope: ['profile', 'email'],
        state: JSON.stringify({ clientApiKey, redirectUri })
    })(req, res, next);
});

router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/login', session: false }),
    async (req, res) => {
        try {
            const { state } = req.query;
            const { clientApiKey, redirectUri } = JSON.parse(state);

            // Verify client API key
            const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
            if (!client) {
                return res.redirect(`${redirectUri}?error=invalid_client`);
            }

            const user = req.user;

            // Generate tokens
            const accessToken = jwt.sign(
                { userId: user._id, email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
            );

            const refreshToken = jwt.sign(
                { userId: user._id },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
            );

            // Save refresh token
            await Token.create({
                token: refreshToken,
                userId: user._id,
                type: 'refresh',
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                clientId: client._id
            });

            // Create audit log
            const auditLog = {
                action: 'google_oauth_login',
                userId: user._id,
                clientId: client._id,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                status: 'success'
            };

            rabbitMQService.sendToQueue('audit_log_queue', auditLog);

            // Redirect with tokens
            res.redirect(`${redirectUri}?accessToken=${accessToken}&refreshToken=${refreshToken}`);
        } catch (error) {
            console.error('Google OAuth callback error:', error);
            res.redirect(`${req.session.redirectUri}?error=server_error`);
        }
    }
);

// GitHub OAuth routes (similar to Google)
router.get('/github', (req, res, next) => {
    const { clientApiKey, redirectUri } = req.query;

    if (!clientApiKey || !redirectUri) {
        return res.status(400).json({
            status: 'error',
            message: 'clientApiKey and redirectUri are required'
        });
    }

    passport.authenticate('github', {
        scope: ['user:email'],
        state: JSON.stringify({ clientApiKey, redirectUri })
    })(req, res, next);
});

router.get('/github/callback',
    passport.authenticate('github', { failureRedirect: '/login', session: false }),
    async (req, res) => {
        try {
            const { state } = req.query;
            const { clientApiKey, redirectUri } = JSON.parse(state);

            // Verify client API key
            const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
            if (!client) {
                return res.redirect(`${redirectUri}?error=invalid_client`);
            }

            const user = req.user;

            // Generate tokens
            const accessToken = jwt.sign(
                { userId: user._id, email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
            );

            const refreshToken = jwt.sign(
                { userId: user._id },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
            );

            // Save refresh token
            await Token.create({
                token: refreshToken,
                userId: user._id,
                type: 'refresh',
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                clientId: client._id
            });

            // Create audit log
            const auditLog = {
                action: 'github_oauth_login',
                userId: user._id,
                clientId: client._id,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                status: 'success'
            };

            rabbitMQService.sendToQueue('audit_log_queue', auditLog);

            // Redirect with tokens
            res.redirect(`${redirectUri}?accessToken=${accessToken}&refreshToken=${refreshToken}`);
        } catch (error) {
            console.error('GitHub OAuth callback error:', error);
            res.redirect(`${req.session.redirectUri}?error=server_error`);
        }
    }
);

// Refresh token
router.post('/refresh-token', [
    body('refreshToken').notEmpty().withMessage('Refresh token is required'),
    body('clientApiKey').notEmpty().withMessage('Client API key is required')
], async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { refreshToken, clientApiKey } = req.body;

        // Verify client API key
        const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid client API key'
            });
        }

        // Verify refresh token
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (error) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid refresh token'
            });
        }

        // Check if token exists in database and is not blacklisted
        const tokenDoc = await Token.findOne({
            token: refreshToken,
            type: 'refresh',
            blacklisted: false,
            expiresAt: { $gt: new Date() }
        });

        if (!tokenDoc) {
            return res.status(401).json({
                status: 'error',
                message: 'Refresh token not found or expired'
            });
        }

        // Find user
        const user = await User.findById(decoded.userId);
        if (!user || user.isBlocked) {
            return res.status(401).json({
                status: 'error',
                message: 'User not found or account blocked'
            });
        }

        // Generate new access token
        const newAccessToken = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
        );

        // Create audit log
        const auditLog = {
            action: 'token_refreshed',
            userId: user._id,
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Token refreshed successfully',
            data: {
                accessToken: newAccessToken,
                refreshToken // Return the same refresh token
            }
        });
    } catch (error) {
        next(error);
    }
});

// Logout
router.post('/logout', [
    body('refreshToken').notEmpty().withMessage('Refresh token is required'),
    body('clientApiKey').notEmpty().withMessage('Client API key is required')
], async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { refreshToken, clientApiKey } = req.body;

        // Verify client API key
        const client = await Client.findOne({ apiKey: clientApiKey, isActive: true });
        if (!client) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid client API key'
            });
        }

        // Blacklist the refresh token
        await Token.updateOne(
            { token: refreshToken, type: 'refresh' },
            { blacklisted: true }
        );

        // Create audit log
        const auditLog = {
            action: 'logout',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Logged out successfully'
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router;