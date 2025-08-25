// models/AuditLog.js
const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
    action: {
        type: String,
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    clientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Client'
    },
    ipAddress: String,
    userAgent: String,
    metadata: mongoose.Schema.Types.Mixed,
    status: {
        type: String,
        enum: ['success', 'failure'],
        required: true
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Login_AuditLog', AuditLogSchema);