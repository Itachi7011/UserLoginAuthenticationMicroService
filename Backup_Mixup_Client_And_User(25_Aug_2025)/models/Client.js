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
    branding: {
        logo: {
            data: String,
            originalFileName: String,
            publicId: String,
            contentType: String,
        },
        primaryColor: { type: String, default: '#2563eb' },
        companyName: String,
        termsUrl: String,
        privacyPolicyUrl: String
    },
    website: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                // More flexible validation
                return /^(https?:\/\/)?[^\s/$.?#].[^\s]*$/.test(v);
            },
            message: "Please enter a valid website URL"
        }
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
    authConfig: {
        allowedRedirectURIs: [{
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/.test(v);
                },
                message: "Please enter a valid redirect URI"
            }
        }],
        allowedOrigins: [String],
        tokenExpiration: {
            accessToken: {
                type: Number,
                default: 3600 // 1 hour in seconds
            },
            refreshToken: {
                type: Number,
                default: 2592000 // 30 days in seconds
            }
        },
        requireEmailVerification: {
            type: Boolean,
            default: true
        },
        enableMFA: {
            type: Boolean,
            default: false
        },
        passwordPolicy: {
            minLength: {
                type: Number,
                default: 8
            },
            requireNumbers: {
                type: Boolean,
                default: true
            },
            requireSymbols: {
                type: Boolean,
                default: true
            },
            requireUppercase: {
                type: Boolean,
                default: true
            }
        }
    },
    subscription: {
        plan: {
            type: String,
            enum: ['free', 'starter', 'professional', 'enterprise'],
            default: 'free'
        },
        maxUsers: {
            type: Number,
            default: 100
        },
        currentUsers: {
            type: Number,
            default: 0
        },
        monthlyRequests: {
            type: Number,
            default: 10000
        },
        features: [String],
        expiresAt: Date
    },
    rateLimiting: {
        requestsPerMinute: {
            type: Number,
            default: 60
        },


    },
    webhooks: {
        url: String,
        secret: String,
        events: [{
            type: String,
            enum: [
                'user:signup',
                'user:login',
                'user:logout',
                'user:password_reset',
                'user:email_verified',
                'user:blocked',
                'user:deleted'
            ]
        }],
        isActive: {
            type: Boolean,
            default: false
        }
    },
    lastApiCall: { type: Date, default: Date.now },
    totalRequests: { type: Number, default: 0 },
    lastWebhookSent: Date,
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
    otp: {
        type: String,
        required: true,
        unique: true
    },
    otpTemplate: {
        subject: String,
        message: String,
        expiration: {
            type: Number,
            default: 10 // minutes
        }
    },
    tokens: [{
        token: {
            type: String,
        },
        tokenType: {
            type: String,
            enum: ['access', 'refresh', 'password_reset', 'email_verification'],
            default: 'access'
        },
        expiration: {
            type: Date,
            default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days from now
        },
        createdAt: {
            type: Date,
            default: Date.now
        },
        isRevoked: {
            type: Boolean,
            default: false
        },
        deviceInfo: {
            userAgent: {
                type: String
            },
            ipAddress: {
                type: String
            }
        },
        scope: {
            type: [String],
            enum: [
                'client:read',
                'client:write',
                'client:delete',
                'client:profile:read',
                'client:profile:write',
                'client:billing:read',
                'client:billing:write',
                'client:subscription:read',
                'client:subscription:write',
                'client:api:read',
                'client:api:write',
                'client:files:read',
                'client:files:write',
                'client:settings:read',
                'client:settings:write'
            ],
            default: ['client:read']
        }
    }],
    oauth: {
        googleId: String,
        githubId: String,
        profile: mongoose.Schema.Types.Mixed
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    lastLogin: Date,

}, {
    timestamps: true
});


ClientSchema.index({ email: 1 });
ClientSchema.index({ apiKey: 1 });
ClientSchema.index({ 'tokens.token': 1 }); // For faster token lookups
ClientSchema.index({ isActive: 1, isBlocked: 1 }); // For filtering active clients

ClientSchema.methods.generateSecureKeys = function () {
    const crypto = require('crypto');
    this.apiKey = 'cl_' + crypto.randomBytes(24).toString('hex');
    this.secretKey = 'cl_sec_' + crypto.randomBytes(32).toString('hex');
};

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
ClientSchema.methods.incrementLoginAttempts = async function () {
    const MAX_ATTEMPTS = 5; // Hardcode or use config
    const LOCKOUT_DURATION = 2 * 60 * 60 * 1000; // 2 hours

    if (this.lockUntil && this.lockUntil < Date.now()) {
        // Reset if lock expired
        this.loginAttempts = 1;
        this.lockUntil = undefined;
        return this.save();
    }

    this.loginAttempts += 1;

    if (this.loginAttempts >= MAX_ATTEMPTS && !this.isLocked) {
        this.lockUntil = Date.now() + LOCKOUT_DURATION;
    }

    return this.save();
};

module.exports = mongoose.model('Login_Saas_Client', ClientSchema);