import express from 'express';
import admin from 'firebase-admin';  // Correctly import Firebase Admin SDK
import bcrypt from 'bcryptjs';
import session from 'express-session';
import axios from 'axios';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Load environment variables from .env file
dotenv.config();

// Load Firebase service account key using fs (since ES modules don't support require)
const service_account = JSON.parse(fs.readFileSync(path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT_PATH), 'utf-8'));

// Initialize Firebase Admin SDK with the service account credentials
admin.initializeApp({
  credential: admin.credential.cert(service_account),  // Initialize Firebase with the service account
});
const db = admin.firestore();  // Initialize Firestore // Firebase Firestore

// Confirm Firebase connection
console.log("Firebase Admin SDK initialized successfully.");

// Check if OMDb API Key is loaded successfully
const omdbApiKey = process.env.OMDB_API_KEY;
if (!omdbApiKey) {
    console.error("OMDb API key is not set in the environment variables.");
} else {
    console.log("OMDb API key loaded successfully.");
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);  // This will give you the directory path

// Setup Express App
const app = express();
const port = process.env.PORT || 17000;

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form data
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files
app.set('view engine', 'ejs'); // Using EJS as view engine

// Session management
app.use(session({
    secret: 'secretKey', // Secret key to sign session cookie
    resave: false,
    saveUninitialized: true
}));

// OMDb API URL
const apiUrl = 'https://www.omdbapi.com/';

// Routes

// Home Page (Index)
app.get('/', (req, res) => {
    res.render('index');
});

// Sign Up Page
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Sign In Page
app.get('/signin', (req, res) => {
    res.render('signin');
});

// Dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/signin');
    }
    res.render('dashboard', { user: req.session.user });
});

// Sign Up Route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password

    try {
        // Check if user already exists
        const userSnapshot = await db.collection('users').where('username', '==', username).get();
        if (!userSnapshot.empty) {
            return res.status(400).send('User already exists');
        }

        // Create new user document
        await db.collection('users').add({
            username,
            password: hashedPassword
        });
        res.redirect('/signin');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error signing up user');
    }
});

// Sign In Route
app.post('/signin', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if user exists
        const userSnapshot = await db.collection('users').where('username', '==', username).get();
        if (userSnapshot.empty) {
            return res.status(400).send('User not found');
        }

        const user = userSnapshot.docs[0].data();

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid password');
        }

        // Create session
        req.session.user = { username: user.username };
        res.redirect('/dashboard');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error signing in user');
    }
});

// Movie Search Route
app.post('/search-movie', async (req, res) => {
    const movieName = req.body.movieName;

    if (!movieName) {
        return res.status(400).send("Movie name is required");
    }

    try {
        const response = await axios.get(apiUrl, {
            params: {
                t: movieName,
                apikey: omdbApiKey
            }
        });

        console.log('API Response:', response.data);  // Log the full response for inspection

        if (response.data.Response === 'False') {
            return res.status(404).send("Movie not found");
        }

        res.render('movie-details', {
            title: response.data.Title,
            director: response.data.Director,
            actors: response.data.Actors,
            genre: response.data.Genre,
            plot: response.data.Plot,
            year: response.data.Year,
            poster: response.data.Poster,
            imdbRating: response.data.imdbRating,
            imdbVotes: response.data.imdbVotes
        });

    } catch (error) {
        console.error("OMDb API Error:", error);
        res.status(500).send("Error fetching movie details");
    }
});

// Start Server
app.listen(port, () => {
    console.log(`server is running on http://localhost:${port}`);
});
