// routes/clients.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const { authenticate, authorize } = require('../middleware/auth');
const Client = require('../models/Client');
const AuditLog = require('../models/AuditLog');
const rabbitMQService = require('../services/rabbitmq');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { generateOTP, sendOTPEmail, sendWelcomeEmail } = require('../services/emailService');

const router = express.Router();

// Generate JWT token for client
const generateClientToken = (client) => {
    return jwt.sign(
        {
            clientId: client._id,
            apiKey: client.apiKeys[0]?.apiKey
        },
        process.env.JWT_SECRET || 'your_jwt_secret',
        { expiresIn: '24h' }
    );
};



// Only admins can access client management routes
// router.use(authenticate, authorize('admin'));
// router.use(authenticate);



// Client registration (Public)
router.post('/register', [
    body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('website').isURL().withMessage('Please provide a valid website URL'),
    body('description').optional().trim(),
    body('branding.companyName').optional().trim(),
], async (req, res, next) => {
    try {

        console.log(req.body)
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { name, email, password, website, branding = {}, description } = req.body;

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

        // Generate OTP
        const otp = generateOTP();
        const companyName = process.env.APP_NAME;

        // Create new client
        const client = new Client({
            name,
            email,
            password,
            website,
            description,
            otp, // Store OTP in database
            emailVerified: false,
            // Auto-generate API and secret keys

            otpTemplate: {
                expiration: 15, // 15 minutes expiration
                subject: `Verify Your ${companyName} Account`
            }
        });

        client.generateSecureKeys('Primary API key', ['read', 'write', 'admin']);


        await client.save();

        // Send OTP email (don't await to avoid blocking response)
        sendOTPEmail(email, name, companyName, otp, 15)
            .then(result => {
                if (!result.success) {
                    console.error('Failed to send OTP email:', result.error);
                    // You might want to log this to a monitoring service
                }
            })
            .catch(error => {
                console.error('Error in email sending process:', error);
            });

        // Generate JWT token
        const token = generateClientToken(client);

        // Create audit log
        const auditLog = {
            action: 'client_registered',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { clientName: client.name }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);



        res.status(201).json({
            status: 'success',
            message: 'Client registered successfully. Please check your email for verification OTP.',
            data: {
                client: {
                    id: client._id,
                    name: client.name,
                    email: client.email,
                    website: client.website,
                    apiKey: client.apiKey
                },
                token,
                requiresEmailVerification: true
            }
        });
    } catch (error) {
        next(error);
    }
});

// Client login with email/password (Public)
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
            isDeleted: false,
            isBlocked: false
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



        // Generate JWT token
        const token = generateClientToken(client);

        // Add token to client's tokens array
        client.tokens.push({
            token,
            tokenType: 'access',
            expiration: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
            deviceInfo: {
                userAgent: req.get('User-Agent'),
                ipAddress: req.ip
            }
        });

        // Reset login attempts on successful login
        client.loginAttempts = 0;
        client.lockUntil = null;
        client.lastLogin = new Date();

        await client.save();

        res.json({
            status: 'success',
            message: 'Client authenticated successfully',
            data: {
                client: {
                    id: client._id,
                    name: client.name,
                    email: client.email,
                    website: client.website,
                    subscription: client.subscription
                },
                token
            }
        });
    } catch (error) {
        next(error);
    }
});

// Get client profile (Protected)
router.get('/profile', async (req, res, next) => {
    try {
        // Extract client ID from token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required'
            });
        }

        const token = authHeader.split(' ')[1];

        // Add try-catch specifically for JWT verification
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');

        } catch (jwtError) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid or expired token',
                error: jwtError.message
            });
        }

        const client = await Client.findById(decoded.clientId)
            .select('-password -tokens -__v');

        if (!client || client.isDeleted) {
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

// Add this route for profile updates
router.put('/profile', [
    body('name').optional().trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('website').optional().isURL().withMessage('Please provide a valid website URL').optional({ nullable: true, checkFalsy: true }),
    body('branding.companyName').optional().trim().optional({ nullable: true, checkFalsy: true }),
    body('branding.primaryColor').optional().isHexColor().withMessage('Please provide a valid hex color').optional({ nullable: true, checkFalsy: true }),
    body('branding.termsUrl').optional().isURL().withMessage('Please provide a valid URL').optional({ nullable: true, checkFalsy: true }),
    body('branding.privacyPolicyUrl').optional().isURL().withMessage('Please provide a valid URL').optional({ nullable: true, checkFalsy: true }),
    body('authConfig.enableMFA').optional().isBoolean().withMessage('MFA setting must be boolean'),
    body('authConfig.requireEmailVerification').optional().isBoolean().withMessage('Email verification setting must be boolean'),
    body('webhooks.url').optional().isURL().withMessage('Please provide a valid webhook URL').optional({ nullable: true, checkFalsy: true }),
    body('webhooks.isActive').optional().isBoolean().withMessage('Webhook status must be boolean')
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

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required'
            });
        }

        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
        } catch (jwtError) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid or expired token'
            });
        }

        const client = await Client.findById(decoded.clientId);
        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Prepare update data
        const updateData = {};
        const updatedFields = [];

        // Handle nested field updates and null values
        Object.keys(req.body).forEach(key => {
            if (req.body[key] === null || req.body[key] === '') {
                // Handle null/empty values by setting to undefined (which will remove the field)
                if (key.includes('.')) {
                    const [parent, child] = key.split('.');
                    if (!updateData[parent]) {
                        updateData[parent] = client[parent] ? client[parent].toObject() : {};
                    }
                    updateData[parent][child] = undefined;
                } else {
                    updateData[key] = undefined;
                }
                updatedFields.push(key);
            } else if (key.includes('.')) {
                const [parent, child] = key.split('.');
                if (!updateData[parent]) {
                    updateData[parent] = client[parent] ? client[parent].toObject() : {};
                }
                updateData[parent][child] = req.body[key];
                updatedFields.push(key);
            } else {
                updateData[key] = req.body[key];
                updatedFields.push(key);
            }
        });

        // Use $set and $unset to properly handle null values
        const setData = {};
        const unsetData = {};

        Object.keys(updateData).forEach(key => {
            if (typeof updateData[key] === 'object' && updateData[key] !== null) {
                Object.keys(updateData[key]).forEach(subKey => {
                    const fullKey = `${key}.${subKey}`;
                    if (updateData[key][subKey] === undefined) {
                        unsetData[fullKey] = "";
                    } else {
                        if (!setData[key]) setData[key] = {};
                        setData[key][subKey] = updateData[key][subKey];
                    }
                });
            } else if (updateData[key] === undefined) {
                unsetData[key] = "";
            } else {
                setData[key] = updateData[key];
            }
        });

        const updateOperation = {};
        if (Object.keys(setData).length > 0) {
            updateOperation.$set = setData;
        }
        if (Object.keys(unsetData).length > 0) {
            updateOperation.$unset = unsetData;
        }

        // Update client
        const updatedClient = await Client.findByIdAndUpdate(
            decoded.clientId,
            updateOperation,
            { new: true, runValidators: true }
        ).select('-password -tokens -__v');

        // Create audit log
        const auditLog = {
            action: 'client_profile_updated',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { updatedFields }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Profile updated successfully',
            data: { client: updatedClient }
        });
    } catch (error) {
        next(error);
    }
});

// Add API key generation endpoint
router.post('/api-keys/generate', [
    body('description').optional().trim().isLength({ max: 100 }).withMessage('Description must be less than 100 characters')
], async (req, res, next) => {
    try {
        console.log(req.body)
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required'
            });
        }

        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
        } catch (jwtError) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid or expired token'
            });
        }

        const client = await Client.findById(decoded.clientId);
        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        const { description } = req.body;
        const newKeySet = client.generateSecureKeys(description, ['read', 'write']);

        await client.save();

        // Create audit log
        const auditLog = {
            action: 'api_key_generated',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'API key generated successfully',
            data: {
                apiKey: newKeySet.apiKey,
                secretKey: newKeySet.secretKey
            }
        });
    } catch (error) {
        next(error);
    }
});

// Add API key toggle endpoint
router.put('/api-keys/:keyId/toggle', async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required'
            });
        }

        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
        } catch (jwtError) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid or expired token'
            });
        }

        const client = await Client.findById(decoded.clientId);
        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        const apiKey = client.apiKeys.id(req.params.keyId);
        if (!apiKey) {
            return res.status(404).json({
                status: 'error',
                message: 'API key not found'
            });
        }

        apiKey.isActive = !apiKey.isActive;
        await client.save();

        // Create audit log
        const auditLog = {
            action: 'api_key_toggled',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: {
                keyId: req.params.keyId,
                newStatus: apiKey.isActive ? 'active' : 'inactive'
            }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: `API key ${apiKey.isActive ? 'activated' : 'deactivated'} successfully`,
            data: { isActive: apiKey.isActive }
        });
    } catch (error) {
        next(error);
    }
});

// Get all clients (Admin only)
router.get('/', async (req, res, next) => {
    try {
        const { page = 1, limit = 10, search } = req.query;
        const skip = (page - 1) * limit;

        const filter = { isDeleted: false };
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { website: { $regex: search, $options: 'i' } },
                { apiKey: { $regex: search, $options: 'i' } }
            ];
        }

        const clients = await Client.find(filter)
            .select('-password -tokens -__v')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

        const total = await Client.countDocuments(filter);

        res.json({
            status: 'success',
            data: {
                clients,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        next(error);
    }
});

// Get client by ID (Admin only)
router.get('/:id', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id)
            .select('-password -tokens -__v');

        if (!client || client.isDeleted) {
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

// Create new client (Admin only)
router.post('/admin/create', [
    body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('website').isURL().withMessage('Please provide a valid website URL'),
    body('description').optional().trim(),
    body('otpTemplate.expiration').optional().isInt({ min: 1, max: 60 }).withMessage('OTP expiration must be between 1-60 minutes'),
    body('otpTemplate.subject').optional().trim()
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

        const { name, email, website, description, otpTemplate } = req.body;

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

        // Generate a temporary password
        const tempPassword = crypto.randomBytes(12).toString('hex');

        // Create new client
        const client = new Client({
            name,
            email,
            password: tempPassword, // Will be hashed by pre-save hook
            website,
            description,
            apiKey: 'cl_' + crypto.randomBytes(24).toString('hex'),
            secretKey: 'cl_sec_' + crypto.randomBytes(32).toString('hex'),
            otpTemplate: {
                expiration: otpTemplate?.expiration || 15,
                subject: otpTemplate?.subject || 'Your Verification Code'
            }
        });

        await client.save();

        // Create audit log
        const auditLog = {
            action: 'client_created',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { clientName: client.name }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.status(201).json({
            status: 'success',
            message: 'Client created successfully',
            data: {
                client: {
                    id: client._id,
                    name: client.name,
                    email: client.email,
                    website: client.website,
                    apiKey: client.apiKey
                },
                tempPassword // Send temporary password (should be sent via secure channel)
            }
        });
    } catch (error) {
        next(error);
    }
});

// Update client (Admin only)
router.put('/admin/:id', [
    body('name').optional().trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').optional().isEmail().withMessage('Please provide a valid email'),
    body('website').optional().isURL().withMessage('Please provide a valid website URL'),
    body('description').optional().trim(),
    body('otpTemplate.expiration').optional().isInt({ min: 1, max: 60 }).withMessage('OTP expiration must be between 1-60 minutes'),
    body('otpTemplate.subject').optional().trim()
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

        const client = await Client.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        ).select('-password -tokens -__v');

        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Create audit log
        const auditLog = {
            action: 'client_updated',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { clientName: client.name }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Client updated successfully',
            data: { client }
        });
    } catch (error) {
        next(error);
    }
});

// Regenerate API key (Admin only)
router.post('/admin/:id/regenerate-api-key', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id);

        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Generate new API key
        const newApiKey = 'cl_' + crypto.randomBytes(24).toString('hex');
        client.apiKey = newApiKey;
        client.apiKeyLastRotated = new Date();
        await client.save();

        // Create audit log
        const auditLog = {
            action: 'api_key_regenerated',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { clientName: client.name }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'API key regenerated successfully',
            data: { apiKey: newApiKey }
        });
    } catch (error) {
        next(error);
    }
});

// Toggle client status (Admin only)
router.patch('/admin/:id/status', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id);

        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        client.isActive = !client.isActive;
        await client.save();

        // Create audit log
        const auditLog = {
            action: 'client_status_toggled',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: {
                clientName: client.name,
                newStatus: client.isActive ? 'active' : 'inactive'
            }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: `Client ${client.isActive ? 'activated' : 'deactivated'} successfully`,
            data: { isActive: client.isActive }
        });
    } catch (error) {
        next(error);
    }
});

// Delete client (soft delete) (Admin only)
router.delete('/admin/:id', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id);

        if (!client || client.isDeleted) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Soft delete
        client.isDeleted = true;
        client.deletedAt = new Date();
        await client.save();

        // Create audit log
        const auditLog = {
            action: 'client_deleted',
            clientId: client._id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { clientName: client.name }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Client deleted successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Google OAuth for clients (Public)
router.get('/auth/google',
    passport.authenticate('client-google', {
        scope: ['profile', 'email'],
        session: false
    })
);

router.get('/auth/google/callback',
    passport.authenticate('client-google', {
        failureRedirect: '/client-login?error=auth_failed',
        session: false
    }),
    async (req, res) => {
        try {
            // Generate JWT token
            const token = generateClientToken(req.user);

            // Add token to client's tokens array
            req.user.tokens.push({
                token,
                tokenType: 'access',
                expiration: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
                deviceInfo: {
                    userAgent: req.get('User-Agent'),
                    ipAddress: req.ip
                }
            });

            await req.user.save();

            // Redirect to CLIENT-SIDE dashboard with token in URL params
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-dashboard?token=${token}&clientId=${req.user._id}`);
        } catch (error) {
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-login?error=token_generation_failed`);
        }
    }
);

// GitHub OAuth for clients (Public)
router.get('/auth/github',
    passport.authenticate('client-github', {
        scope: ['user:email'],
        session: false
    })
);

router.get('/auth/github/callback',
    passport.authenticate('client-github', {
        failureRedirect: '/client-login?error=auth_failed',
        session: false
    }),
    async (req, res) => {
        try {
            const token = generateClientToken(req.user);

            // Add token to client's tokens array
            req.user.tokens.push({
                token,
                tokenType: 'access',
                expiration: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
                deviceInfo: {
                    userAgent: req.get('User-Agent'),
                    ipAddress: req.ip
                }
            });

            await req.user.save();

            // Redirect to CLIENT-SIDE
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-dashboard?token=${token}&clientId=${req.user._id}`);
        } catch (error) {
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/client-login?error=token_generation_failed`);
        }
    }
);

// Verify client email with OTP
router.post('/verify-email', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
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

        const { email, otp } = req.body;

        // Find client by email
        const client = await Client.findOne({
            email,
            isActive: true,
            isDeleted: false,
            isBlocked: false
        });

        if (!client) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        if (client.emailVerified) {
            return res.status(400).json({
                status: 'error',
                message: 'Email already verified'
            });
        }

        // Check if OTP matches and is not expired
        if (!client.otp || client.otp !== otp) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid OTP'
            });
        }

        // Verify email
        client.emailVerified = true;
        client.otp = undefined; // Clear OTP after successful verification
        await client.save();

        // Create audit log
        const auditLog = {
            action: 'client_email_verified',
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

// Resend OTP for client
router.post('/resend-otp', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('type').isIn(['email_verification', 'password_reset', '2fa']).withMessage('Invalid OTP type')
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

        const { email, type } = req.body;

        // Find client
        const client = await Client.findOne({
            email,
            isActive: true,
            isDeleted: false,
            isBlocked: false
        });

        if (!client) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Check if email is already verified for verification OTPs
        if (type === 'email_verification' && client.emailVerified) {
            return res.status(400).json({
                status: 'error',
                message: 'Email already verified'
            });
        }

        // Generate new OTP
        const otp = crypto.randomInt(100000, 999999).toString();

        // Store OTP in client document
        client.otp = otp;
        await client.save();

        // Send OTP via email using RabbitMQ
        const emailData = {
            to: email,
            subject: type === 'password_reset'
                ? 'Password Reset Request'
                : client.otpTemplate?.subject || 'Your Verification Code',
            template: 'otp',
            context: {
                name: client.name,
                otp,
                website: client.website,
                company: client.name,
                expiration: client.otpTemplate?.expiration || 10,
                purpose: type === 'password_reset' ? 'password reset' : 'verification'
            }
        };

        rabbitMQService.sendToQueue('email_queue', emailData);

        // Create audit log
        const auditLog = {
            action: 'client_otp_resent',
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

// Refresh token for client
router.post('/refresh-token', [
    body('refreshToken').notEmpty().withMessage('Refresh token is required')
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

        const { refreshToken } = req.body;

        // Verify refresh token
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || 'your_jwt_secret');
        } catch (error) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid refresh token'
            });
        }

        // Find client
        const client = await Client.findById(decoded.clientId);
        if (!client || client.isBlocked || !client.isActive || client.isDeleted) {
            return res.status(401).json({
                status: 'error',
                message: 'Client not found or account blocked'
            });
        }

        // Check if refresh token exists in client's tokens and is not revoked
        const refreshTokenDoc = client.tokens.find(token =>
            token.token === refreshToken &&
            token.tokenType === 'refresh' &&
            !token.isRevoked &&
            token.expiration > new Date()
        );

        if (!refreshTokenDoc) {
            return res.status(401).json({
                status: 'error',
                message: 'Refresh token not found or expired'
            });
        }

        // Generate new access token
        const newAccessToken = jwt.sign(
            { clientId: client._id, apiKey: client.apiKey },
            process.env.JWT_SECRET || 'your_jwt_secret',
            { expiresIn: '15m' }
        );

        // Add new access token to client's tokens
        client.tokens.push({
            token: newAccessToken,
            tokenType: 'access',
            expiration: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
            deviceInfo: {
                userAgent: req.get('User-Agent'),
                ipAddress: req.ip
            }
        });

        await client.save();

        // Create audit log
        const auditLog = {
            action: 'client_token_refreshed',
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

// Logout client
router.post('/logout', [
    body('refreshToken').notEmpty().withMessage('Refresh token is required')
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

        const { refreshToken } = req.body;

        // Verify refresh token to get client ID
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || 'your_jwt_secret');
        } catch (error) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid refresh token'
            });
        }

        // Find client and revoke the refresh token
        const client = await Client.findById(decoded.clientId);
        if (client) {
            // Revoke the specific refresh token
            const tokenIndex = client.tokens.findIndex(token =>
                token.token === refreshToken && token.tokenType === 'refresh'
            );

            if (tokenIndex !== -1) {
                client.tokens[tokenIndex].isRevoked = true;
                await client.save();
            }
        }

        // Create audit log
        const auditLog = {
            action: 'client_logout',
            clientId: decoded.clientId,
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

// Logout from all devices (revoke all tokens)
router.post('/logout-all', async (req, res, next) => {
    try {
        // Extract client ID from token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required'
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');

        // Find client and revoke all tokens
        const client = await Client.findById(decoded.clientId);
        if (client) {
            // Revoke all tokens
            client.tokens.forEach(token => {
                token.isRevoked = true;
            });

            await client.save();
        }

        // Create audit log
        const auditLog = {
            action: 'client_logout_all',
            clientId: decoded.clientId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Logged out from all devices successfully'
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router;