// routes/users.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const { authenticate, authorize } = require('../middleware/auth');
const User = require('../models/User');
const Token = require('../models/Token');
const AuditLog = require('../models/AuditLog');
const rabbitMQService = require('../services/rabbitmq');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Apply authentication to all routes
router.use(authenticate);

// Get current user profile
router.get('/profile', async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId).select('-password -loginAttempts -lockUntil');

        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        res.json({
            status: 'success',
            data: { user }
        });
    } catch (error) {
        next(error);
    }
});

// Update user profile
router.put('/profile', [
    body('name').optional().trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').optional().isEmail().withMessage('Please provide a valid email')
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

        const { name, email } = req.body;
        const updateData = {};

        if (name) updateData.name = name;
        if (email && email !== req.user.email) {
            // If changing email, require re-verification
            updateData.email = email;
            updateData.emailVerified = false;
        }

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            updateData,
            { new: true, runValidators: true }
        ).select('-password -loginAttempts -lockUntil');

        // Create audit log
        const auditLog = {
            action: 'profile_updated',
            userId: req.user.userId,
            clientId: req.user.clientId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { updatedFields: Object.keys(updateData) }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Profile updated successfully',
            data: { user }
        });
    } catch (error) {
        next(error);
    }
});

// Change password
router.post('/change-password', [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
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

        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await user.comparePassword(currentPassword);
        if (!isCurrentPasswordValid) {
            // Create audit log for failed attempt
            const auditLog = {
                action: 'password_change_failed',
                userId: req.user.userId,
                clientId: req.user.clientId,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                status: 'failure',
                metadata: { reason: 'Invalid current password' }
            };

            rabbitMQService.sendToQueue('audit_log_queue', auditLog);

            return res.status(400).json({
                status: 'error',
                message: 'Current password is incorrect'
            });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        // Invalidate all existing refresh tokens (force logout from all devices)
        await Token.updateMany(
            { userId: req.user.userId, type: 'refresh' },
            { blacklisted: true }
        );

        // Create audit log
        const auditLog = {
            action: 'password_changed',
            userId: req.user.userId,
            clientId: req.user.clientId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Password changed successfully. Please login again.'
        });
    } catch (error) {
        next(error);
    }
});

// Google OAuth for clients
const generateUserToken = (user) => {
  return jwt.sign(
    {
      userId: user._id,
      email: user.email,
      role: user.role,
      type: 'user'
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );
};

// Google OAuth for users
router.get('/google',
  passport.authenticate('user-google', {
    scope: ['profile', 'email'],
    session: false
  })
);

router.get('/google/callback',
  passport.authenticate('user-google', {
    failureRedirect: '/user-login?error=auth_failed',
    session: false
  }),
  async (req, res) => {
    try {
      // Generate JWT token
      const token = generateUserToken(req.user);

      // Redirect to USER-SIDE dashboard with token
      res.redirect(`${process.env.USER_URL || 'http://localhost:3000'}/user-dashboard?token=${token}&userId=${req.user._id}`);
    } catch (error) {
      res.redirect(`${process.env.USER_URL || 'http://localhost:3000'}/user-login?error=token_generation_failed`);
    }
  }
);

// GitHub OAuth for users
router.get('/github',
  passport.authenticate('user-github', {
    scope: ['user:email'],
    session: false
  })
);

router.get('/github/callback',
  passport.authenticate('user-github', {
    failureRedirect: '/user-login?error=auth_failed',
    session: false
  }),
  async (req, res) => {
    try {
      const token = generateUserToken(req.user);
      // Redirect to USER-SIDE
      res.redirect(`${process.env.USER_URL || 'http://localhost:3000'}/user-dashboard?token=${token}&userId=${req.user._id}`);
    } catch (error) {
      res.redirect(`${process.env.USER_URL || 'http://localhost:3000'}/user-login?error=token_generation_failed`);
    }
  }
);



// Get active sessions
router.get('/sessions', async (req, res, next) => {
    try {
        const activeSessions = await Token.find({
            userId: req.user.userId,
            type: 'refresh',
            blacklisted: false,
            expiresAt: { $gt: new Date() }
        }).populate('clientId', 'name');

        res.json({
            status: 'success',
            data: { sessions: activeSessions }
        });
    } catch (error) {
        next(error);
    }
});

// Revoke specific session
router.delete('/sessions/:sessionId', async (req, res, next) => {
    try {
        const { sessionId } = req.params;

        const session = await Token.findOneAndUpdate(
            {
                _id: sessionId,
                userId: req.user.userId,
                type: 'refresh'
            },
            { blacklisted: true }
        );

        if (!session) {
            return res.status(404).json({
                status: 'error',
                message: 'Session not found'
            });
        }

        // Create audit log
        const auditLog = {
            action: 'session_revoked',
            userId: req.user.userId,
            clientId: req.user.clientId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            metadata: { sessionId }
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Session revoked successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Revoke all sessions (logout from all devices)
router.delete('/sessions', async (req, res, next) => {
    try {
        await Token.updateMany(
            {
                userId: req.user.userId,
                type: 'refresh',
                blacklisted: false
            },
            { blacklisted: true }
        );

        // Create audit log
        const auditLog = {
            action: 'all_sessions_revoked',
            userId: req.user.userId,
            clientId: req.user.clientId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'All sessions revoked successfully'
        });
    } catch (error) {
        next(error);
    }
});

// Delete account (soft delete)
router.delete('/account', [
    body('password').notEmpty().withMessage('Password is required for account deletion')
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

        const { password } = req.body;
        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Verify password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(400).json({
                status: 'error',
                message: 'Password is incorrect'
            });
        }

        // Soft delete: mark as deleted but keep data for audit purposes
        user.isDeleted = true;
        user.deletedAt = new Date();
        await user.save();

        // Invalidate all sessions
        await Token.updateMany(
            { userId: req.user.userId, type: 'refresh' },
            { blacklisted: true }
        );

        // Create audit log
        const auditLog = {
            action: 'account_deleted',
            userId: req.user.userId,
            clientId: req.user.clientId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success'
        };

        rabbitMQService.sendToQueue('audit_log_queue', auditLog);

        res.json({
            status: 'success',
            message: 'Account deleted successfully'
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router;