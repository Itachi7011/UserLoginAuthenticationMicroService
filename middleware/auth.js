// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Client = require('../models/Client');
const Token = require('../models/Token');

// Authenticate user via JWT
const authenticate = async (req, res, next) => {
    try {
        let token;

        // Check for token in headers
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({
                status: 'error',
                message: 'Access token is required'
            });
        }

        // Verify token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid or expired token'
            });
        }

        // Check if user exists and is not blocked
        const user = await User.findById(decoded.userId).select('-password');
        if (!user || user.isBlocked) {
            return res.status(401).json({
                status: 'error',
                message: 'User not found or account blocked'
            });
        }

        // Check client API key if provided
        if (req.headers['x-client-api-key']) {
            const client = await Client.findOne({
                apiKey: req.headers['x-client-api-key'],
                isActive: true
            });

            if (!client) {
                return res.status(401).json({
                    status: 'error',
                    message: 'Invalid client API key'
                });
            }

            // Verify user belongs to this client
            if (user.clientId.toString() !== client._id.toString()) {
                return res.status(403).json({
                    status: 'error',
                    message: 'User does not belong to this client'
                });
            }

            req.client = client;
        }

        req.user = user;
        next();
    } catch (error) {
        next(error);
    }
};

// Authorize based on roles
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                status: 'error',
                message: 'You do not have permission to perform this action'
            });
        }
        next();
    };
};

// Authorize based on permissions
const hasPermission = (...permissions) => {
    return (req, res, next) => {
        const userPermissions = req.user.permissions || [];

        const hasAllPermissions = permissions.every(permission =>
            userPermissions.includes(permission)
        );

        if (!hasAllPermissions) {
            return res.status(403).json({
                status: 'error',
                message: 'Insufficient permissions'
            });
        }

        next();
    };
};

module.exports = {
    authenticate,
    authorize,
    hasPermission
};
