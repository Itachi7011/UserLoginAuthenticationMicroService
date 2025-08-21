// models/Client.js
const mongoose = require('mongoose');

const ClientSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    website: {
        type: String,
        required: true
    },
    isDeleted: {
        type: Boolean,
        default: false,
    },
    deletedAt: {
        type: Date,
    },
    isBlocked: {
        type: Boolean,
        default: false
    },
    blockedReason: String,
    blockedBy: {
        type: String,
    },
    description: String,
    apiKey: {
        type: String,
        required: true,
        unique: true
    },
    secretKey: {
        type: String,
        required: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    allowedDomains: [String],
    redirectUris: [String],
    subscription: {
        plan: {
            type: String,
            enum: ['free', 'basic', 'premium', 'enterprise'],
            default: 'free'
        },
        expiresAt: Date,
        requestsLimit: Number,
        currentRequests: {
            type: Number,
            default: 0
        }
    },
    otpTemplate: {
        subject: String,
        message: String,
        expiration: {
            type: Number,
            default: 10 // minutes
        }
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Client', ClientSchema);