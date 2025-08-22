const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const Client = require('../models/Client');
const crypto = require('crypto');

// Helper function to generate API key
const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};


// Client Google Strategy
passport.use('client-google', new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/client-auth/google/callback",
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    // Check if client already exists with this Google ID
    let client = await Client.findOne({ 
      'oauth.googleId': profile.id,
      isDeleted: false 
    });

    if (client) {
      return done(null, client);
    }

    // Check if client exists with the same email
    const email = profile.emails && profile.emails[0].value;
    if (email) {
      client = await Client.findOne({ 
        email: email,
        isDeleted: false 
      });
      
      if (client) {
        // Link Google account to existing client
        client.oauth.googleId = profile.id;
        client.oauth.profile = profile;
        await client.save();
        return done(null, client);
      }
    }

    // Create new client (first-time login)
    const apiKey = generateApiKey();
    const secretKey = crypto.randomBytes(16).toString('hex');
    
    client = new Client({
      name: profile.displayName || 'Google OAuth Client',
      email: email,
      website: '', // You might want to prompt for this later
      apiKey,
      secretKey,
      emailVerified: true,
      oauth: {
        googleId: profile.id,
        profile: profile
      }
    });

    await client.save();
    return done(null, client);
  } catch (error) {
    return done(error, null);
  }
}));

// Client GitHub Strategy
// Client GitHub Strategy
passport.use('client-github', new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "/api/client-auth/github/callback",
  passReqToCallback: true,
  scope: ['user:email'] // Ensure email scope is included
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    // Check if client already exists with this GitHub ID
    let client = await Client.findOne({ 
      'oauth.githubId': profile.id,
      isDeleted: false 
    });

    if (client) {
      return done(null, client);
    }

    // Get email from GitHub profile - handle cases where email might be null or private
    let email = null;
    
    // Try to get email from profile emails array
    if (profile.emails && profile.emails.length > 0) {
      email = profile.emails[0].value;
    }
    
    // If no email in profile, try to fetch it using GitHub API
    if (!email) {
      try {
        const response = await fetch('https://api.github.com/user/emails', {
          headers: {
            'Authorization': `token ${accessToken}`,
            'User-Agent': 'Your-App-Name'
          }
        });
        
        if (response.ok) {
          const emails = await response.json();
          const primaryEmail = emails.find(e => e.primary && e.verified);
          if (primaryEmail) {
            email = primaryEmail.email;
          } else if (emails.length > 0) {
            email = emails[0].email;
          }
        }
      } catch (apiError) {
        console.error('Failed to fetch email from GitHub API:', apiError);
      }
    }

    // If still no email, create a placeholder and mark as unverified
    if (!email) {
      email = `github-${profile.id}@placeholder.com`;
    }

    // Check if client exists with the same email (excluding placeholder emails)
    if (email && !email.endsWith('@placeholder.com')) {
      client = await Client.findOne({ 
        email: email,
        isDeleted: false 
      });
      
      if (client) {
        // Link GitHub account to existing client
        client.oauth.githubId = profile.id;
        client.oauth.profile = profile;
        await client.save();
        return done(null, client);
      }
    }

    // Create new client (first-time login)
    const apiKey = generateApiKey();
    const secretKey = crypto.randomBytes(16).toString('hex');
    
    client = new Client({
      name: profile.displayName || profile.username || 'GitHub User',
      email: email,
      website: profile.blog || profile.profileUrl || '',
      apiKey,
      secretKey,
      emailVerified: !email.endsWith('@placeholder.com'), // Only verified if real email
      oauth: {
        githubId: profile.id,
        profile: profile
      }
    });

    await client.save();
    return done(null, client);
  } catch (error) {
    return done(error, null);
  }
}));


passport.serializeUser((client, done) => {
  done(null, client._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const client = await Client.findById(id);
    done(null, client);
  } catch (error) {
    done(error, null);
  }
});


module.exports = passport;