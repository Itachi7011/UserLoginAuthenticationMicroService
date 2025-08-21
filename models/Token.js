// models/Token.js
const mongoose = require('mongoose');

const TokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: ['access', 'refresh', 'password_reset', 'email_verification'],
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    clientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Client'
    },
    blacklisted: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

// Index for automatic expiration
TokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Token', TokenSchema);