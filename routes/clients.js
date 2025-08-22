// routes/clients.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const { authenticate, authorize } = require('../middleware/auth');
const Client = require('../models/Client');
const AuditLog = require('../models/AuditLog');
const rabbitMQService = require('../services/rabbitmq');
const crypto = require('crypto');
const passport = require('passport');

const router = express.Router();

// Only admins can access client management
// router.use(authenticate, authorize('admin'));
// router.use(authenticate);

// Get all clients
router.get('/', async (req, res, next) => {
    try {
        const { page = 1, limit = 10, search } = req.query;
        const skip = (page - 1) * limit;

        const filter = {};
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { website: { $regex: search, $options: 'i' } },
                { apiKey: { $regex: search, $options: 'i' } }
            ];
        }

        const clients = await Client.find(filter)
            .select('-__v')
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

// Get client by ID
router.get('/:id', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id).select('-__v');

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

// Create new client
router.post('/', [
    body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('website').isURL().withMessage('Please provide a valid website URL'),
    body('description').optional().trim(),
    body('otpTemplate.expiration').isInt({ min: 1, max: 60 }).withMessage('OTP expiration must be between 1-60 minutes'),
    body('otpTemplate.subject').optional().trim()
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

        const { name, website, description, otpTemplate } = req.body;

        // Generate unique API key
        const apiKey = crypto.randomBytes(32).toString('hex');

        const client = new Client({
            name,
            website,
            description,
            apiKey,
            otpTemplate: {
                expiration: otpTemplate.expiration || 15,
                subject: otpTemplate.subject || 'Your Verification Code'
            },
            // createdBy: req.user.userId
        });

        await client.save();

        // Create audit log
        const auditLog = {
            action: 'client_created',
            // userId: req.user.userId,
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
            data: { client }
        });
    } catch (error) {
        next(error);
    }
});

// Update client
router.put('/:id', [
    body('name').optional().trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
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
        ).select('-__v');

        if (!client) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Create audit log
        const auditLog = {
            action: 'client_updated',
            userId: req.user.userId,
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

// Regenerate API key
router.post('/:id/regenerate-api-key', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id);

        if (!client) {
            return res.status(404).json({
                status: 'error',
                message: 'Client not found'
            });
        }

        // Generate new API key
        const newApiKey = crypto.randomBytes(32).toString('hex');
        client.apiKey = newApiKey;
        client.apiKeyLastRotated = new Date();
        await client.save();

        // Create audit log
        const auditLog = {
            action: 'api_key_regenerated',
            userId: req.user.userId,
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

// Toggle client status
router.patch('/:id/status', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id);

        if (!client) {
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
            userId: req.user.userId,
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

// Delete client (soft delete)
router.delete('/:id', async (req, res, next) => {
    try {
        const client = await Client.findById(req.params.id);

        if (!client) {
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
            userId: req.user.userId,
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



module.exports = router;