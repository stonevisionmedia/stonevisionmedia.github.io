// Load environment variables
require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const querystring = require('querystring');
const passport = require('passport');
const session = require('express-session');
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware for parsing JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set security headers
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'defaultsecret',
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Configure Passport for Facebook OAuth
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_ID,
      clientSecret: process.env.FB_APP_SECRET,
      callbackURL: process.env.FB_CALLBACK_URL || "https://mediamoney.onrender.com/auth/facebook/callback",
      profileFields: ['id', 'displayName', 'emails'],
    },
    (accessToken, refreshToken, profile, done) => {
      console.log('Facebook OAuth Profile:', profile);
      return done(null, { accessToken, profile });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Authentication middleware for JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.userId = user.userId;
    next();
  });
};

// Basic route to check if the app is running
app.get('/', (req, res) => {
  res.send('App is running');
});

/**
 * User Routes
 */
app.post(
  '/register',
  body('username', 'Username is required').notEmpty(),
  body('email', 'Please include a valid email').isEmail(),
  body('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, email, password } = req.body;

      const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (userResult.rows.length > 0) {
        return res.status(400).json({ msg: 'User already exists' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = await pool.query(
        'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
        [username, email, hashedPassword]
      );

      const payload = { userId: newUser.rows[0].id };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.json({ token });
    } catch (error) {
      console.error('Error during registration:', error);
      next(error);
    }
  }
);

/**
 * Facebook OAuth Routes
 */

// Start Facebook OAuth
app.get('/auth/facebook', passport.authenticate('facebook', {
  scope: ['email', 'pages_show_list', 'instagram_basic', 'instagram_content_publish'],
}));

// Facebook OAuth Callback
app.get(
  '/auth/facebook/callback',
  passport.authenticate('facebook', {
    failureRedirect: '/login',
  }),
  (req, res) => {
    res.json({ user: req.user });
  }
);

/**
 * Instagram OAuth Routes (via Facebook)
 */

// Start Instagram OAuth
app.get('/auth/instagram', (req, res) => {
  const authUrl = 'https://www.facebook.com/v17.0/dialog/oauth?' +
    querystring.stringify({
      client_id: process.env.FB_APP_ID,
      redirect_uri: process.env.FB_REDIRECT_URI,
      scope: 'instagram_basic,instagram_content_publish,pages_show_list',
      response_type: 'code',
    });
  res.redirect(authUrl);
});

// Instagram OAuth Callback
app.get('/auth/instagram/callback', async (req, res, next) => {
  try {
    const { code } = req.query;
    if (!code) {
      return res.status(400).json({ msg: 'Authorization code is missing' });
    }

    const tokenResponse = await axios.get(
      'https://graph.facebook.com/v17.0/oauth/access_token',
      {
        params: {
          client_id: process.env.FB_APP_ID,
          client_secret: process.env.FB_APP_SECRET,
          redirect_uri: process.env.FB_REDIRECT_URI,
          code,
        },
      }
    );

    const userAccessToken = tokenResponse.data.access_token;
    const pagesResponse = await axios.get(
      'https://graph.facebook.com/me/accounts',
      { params: { access_token: userAccessToken } }
    );

    const page = pagesResponse.data.data[0];
    const instagramResponse = await axios.get(
      `https://graph.facebook.com/v17.0/${page.id}`,
      {
        params: {
          fields: 'instagram_business_account',
          access_token: userAccessToken,
        },
      }
    );

    const instagramBusinessAccountId = instagramResponse.data.instagram_business_account.id;

    res.json({
      msg: 'Instagram account linked successfully',
      instagramBusinessAccountId,
    });
  } catch (error) {
    console.error('Error during Instagram OAuth process:', error.response?.data || error.message);
    next(error);
  }
});

/**
 * Instagram Webhook Verification
 */
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token && mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified successfully.');
    res.status(200).send(challenge);
  } else {
    console.error('Webhook verification failed.');
    res.status(403).send('Forbidden');
  }
});

/**
 * Instagram Webhook POST Handling
 */
app.post('/webhook', async (req, res) => {
  const event = req.body;

  // Log the event to the console for debugging
  console.log('Received Instagram Webhook Event:', JSON.stringify(event, null, 2));

  try {
    // Save event to the database
    const query = `
      INSERT INTO webhook_logs (event_id, event_type, event_data)
      VALUES ($1, $2, $3)
    `;
    const values = [
      event.id || null, // Replace with the actual ID from the webhook payload
      event.type || 'unknown', // Replace with the actual event type
      JSON.stringify(event) || '{}',
    ];

    const result = await pool.query(query, values);

    // Debugging: Log the result of the database query
    console.log('Database insert result:', result);

    console.log('Webhook event logged successfully');
  } catch (error) {
    console.error('Error logging webhook event:', error);
  }

  res.status(200).send('Event received');
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: 'An unexpected error occurred' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
