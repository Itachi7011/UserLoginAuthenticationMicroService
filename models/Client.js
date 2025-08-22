const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const ClientSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: function () {
            // Only require email for non-OAuth signups
            return !this.oauth || (!this.oauth.googleId && !this.oauth.githubId);
        },
        unique: true,
        lowercase: true,
        validate: {
            validator: function (v) {
                return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
            },
            message: "Please enter a valid email"
        }
    },
    password: {
        type: String,
        required: function () {
            return !this.oauth.googleId && !this.oauth.githubId;
        },
        minlength: 8
    },
 website: {
        type: String,
        required: true
    },
     apiKey: {
        type: String,
        required: true,
        unique: true
    },
    emailVerified: {
        type: Boolean,
        default: false
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

    isActive: {
        type: Boolean,
        default: true
    },

    otpTemplate: {
        subject: String,
        message: String,
        expiration: {
            type: Number,
            default: 10 // minutes
        }
    },
    oauth: {
        googleId: String,
        githubId: String,
        profile: mongoose.Schema.Types.Mixed
    },
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date
}, {
    timestamps: true
});

// Virtual for checking if account is locked
ClientSchema.virtual('isLocked').get(function () {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Hash password before saving
ClientSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
ClientSchema.methods.comparePassword = async function (candidatePassword) {
    if (!this.password) return false; // For social login clients without password
    return await bcrypt.compare(candidatePassword, this.password);
};

// Increment login attempts
ClientSchema.methods.incrementLoginAttempts = function () {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1 }
        });
    }

    const updates = { $inc: { loginAttempts: 1 } };

    if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
        updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // Lock for 2 hours
    }

    return this.updateOne(updates);
};

module.exports = mongoose.model('Login_Client', ClientSchema);