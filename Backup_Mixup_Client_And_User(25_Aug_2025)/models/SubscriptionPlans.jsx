// models/SubscriptionPlan.js
const mongoose = require('mongoose');

const FeatureSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  key: {
    type: String,
    required: true,
    uppercase: true,
    trim: true
  },
  value: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  description: {
    type: String,
    trim: true
  }
});

const PlanLimitationSchema = new mongoose.Schema({
  maxUsers: {
    type: Number,
    default: null // null means unlimited
  },
  maxDevicesPerUser: {
    type: Number,
    default: 5
  },
  maxSessions: {
    type: Number,
    default: null
  },
  maxApiCalls: {
    type: Number,
    default: 1000
  },
  maxAuditLogsRetention: {
    type: Number, // in days
    default: 30
  },
  maxCustomRoles: {
    type: Number,
    default: 5
  },
  rateLimit: {
    requests: {
      type: Number,
      default: 100
    },
    timeframe: {
      type: Number, // in minutes
      default: 15
    }
  }
});

const SubscriptionPlanSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  tier: {
    type: String,
    enum: ['FREE', 'BASIC', 'PRO', 'ENTERPRISE'],
    required: true,
    uppercase: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  shortDescription: {
    type: String,
    trim: true
  },
  price: {
    monthly: {
      type: Number,
      required: true,
      min: 0
    },
    annually: {
      type: Number,
      min: 0
    },
    currency: {
      type: String,
      default: 'USD',
      uppercase: true
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isDefault: {
    type: Boolean,
    default: false
  },
  features: [FeatureSchema],
  limitations: PlanLimitationSchema,
  authenticationMethods: {
    emailPassword: {
      type: Boolean,
      default: true
    },
    socialLogin: {
      google: { type: Boolean, default: false },
      facebook: { type: Boolean, default: false },
      github: { type: Boolean, default: false },
      linkedin: { type: Boolean, default: false }
    },
    magicLink: {
      type: Boolean,
      default: false
    },
    multiFactor: {
      type: Boolean,
      default: false
    },
    biometric: {
      type: Boolean,
      default: false
    },
    sso: {
      type: Boolean,
      default: false
    },
    customProviders: {
      type: Number,
      default: 0
    }
  },
  securityFeatures: {
    passwordPolicy: {
      minLength: { type: Number, default: 8 },
      requireUppercase: { type: Boolean, default: true },
      requireLowercase: { type: Boolean, default: true },
      requireNumbers: { type: Boolean, default: true },
      requireSpecialChars: { type: Boolean, default: true }
    },
    sessionManagement: {
      type: Boolean,
      default: true
    },
    bruteForceProtection: {
      type: Boolean,
      default: true
    },
    advancedThreatDetection: {
      type: Boolean,
      default: false
    }
  },
  supportLevel: {
    type: String,
    enum: ['COMMUNITY', 'EMAIL', 'CHAT', 'PHONE', 'DEDICATED'],
    default: 'EMAIL'
  },
  sla: {
    uptime: {
      type: Number, // percentage
      default: 99.5
    },
    supportResponseTime: {
      type: Number, // in hours
      default: 48
    }
  },
  trialPeriod: {
    type: Number, // in days
    default: 14
  },
  sortOrder: {
    type: Number,
    default: 0
  },
  metadata: mongoose.Schema.Types.Mixed
}, {
  timestamps: true
});

// Index for efficient querying
SubscriptionPlanSchema.index({ tier: 1, isActive: 1 });
SubscriptionPlanSchema.index({ isDefault: 1 });

module.exports = mongoose.model('Login_Saas_SubscriptionPlan', SubscriptionPlanSchema);