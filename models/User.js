// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
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
            return !this.socialLogin; // Password not required for social logins
        },
        minlength: 8
    },
    phone: {
        type: String,
        validate: {
            validator: function (v) {
                return /^\+?[1-9]\d{1,14}$/.test(v); // E.164 format
            },
            message: "Please enter a valid phone number"
        }
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    phoneVerified: {
        type: Boolean,
        default: false
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    socialLogin: {
        google: {
            id: String,
            token: String
        },
        github: {
            id: String,
            token: String
        }
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'superadmin'],
        default: 'user'
    },
    permissions: [{
        type: String,
        enum: ['read', 'write', 'delete', 'manage_users']
    }],
    website: {
        type: String,
        required: true
    },
    apiKey: {
        type: String,
        required: true,
        unique: true
    },
    secretKey: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true,
        unique: true
    },
    isBlocked: {
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
    blockedReason: String,
    blockedBy: {
        type: String,
    },
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
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
        },
        isActive: {
            type: Boolean,
            default: false
        }
    },
    clientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Client'
    },

    // NEW: Custom attributes field for flexible client-specific data
    customAttributes: {
        type: Map,
        of: mongoose.Schema.Types.Mixed, // Allows any type of value
        default: new Map()
    }
}, {
    timestamps: true,

    // NEW: Transform to convert Map to Object for JSON responses
    toJSON: {
        virtuals: true,
        transform: function (doc, ret) {
            ret.customAttributes = doc.customAttributes ? Object.fromEntries(doc.customAttributes) : {};
            return ret;
        }
    },
    toObject: {
        virtuals: true,
        transform: function (doc, ret) {
            ret.customAttributes = doc.customAttributes ? Object.fromEntries(doc.customAttributes) : {};
            return ret;
        }
    }
});

// Virtual for checking if account is locked
UserSchema.virtual('isLocked').get(function () {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Hash password before saving
UserSchema.pre('save', async function (next) {
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
UserSchema.methods.comparePassword = async function (candidatePassword) {
    if (!this.password) return false; // For social login users without password
    return await bcrypt.compare(candidatePassword, this.password);
};

// NEW: Method to set custom attributes
UserSchema.methods.setCustomAttribute = function (key, value) {
    this.customAttributes.set(key, value);
    return this.save();
};

// NEW: Method to get custom attribute
UserSchema.methods.getCustomAttribute = function (key) {
    return this.customAttributes.get(key);
};

// NEW: Method to remove custom attribute
UserSchema.methods.removeCustomAttribute = function (key) {
    this.customAttributes.delete(key);
    return this.save();
};

// NEW: Method to check if custom attribute exists
UserSchema.methods.hasCustomAttribute = function (key) {
    return this.customAttributes.has(key);
};

// NEW: Method to get all custom attributes as plain object
UserSchema.methods.getAllCustomAttributes = function () {
    return Object.fromEntries(this.customAttributes);
};

// NEW: Method to set multiple custom attributes at once
UserSchema.methods.setMultipleCustomAttributes = function (attributes) {
    for (const [key, value] of Object.entries(attributes)) {
        this.customAttributes.set(key, value);
    }
    return this.save();
};

// NEW: Method to clear all custom attributes
UserSchema.methods.clearCustomAttributes = function () {
    this.customAttributes.clear();
    return this.save();
};

// Increment login attempts
UserSchema.methods.incrementLoginAttempts = function () {
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

module.exports = mongoose.model('Login_User', UserSchema);