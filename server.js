const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
const axios = require('axios');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const schedule = require('node-schedule');
const twilio = require('twilio');
const { isToday, isFuture, parseISO, getDay, getHours, getMinutes, isSameDay } = require('date-fns');

// In a real application, you would load these from your .env file
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const API_KEY = process.env.GEMINI_API_KEY;
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

// Initialize Twilio client
const twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/health_app';
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB:', err));

// Mongoose Schemas
const notificationSchema = new mongoose.Schema({
    reminderAlerts: { type: Boolean, default: true },
    sideEffectAlerts: { type: Boolean, default: true },
    missedDoseReminders: { type: Boolean, default: true }
});

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true },
    age: { type: Number },
    phone: { type: String },
    id_number: { type: String },
    subscription: { type: String, default: 'free' },
    notifications: { type: notificationSchema, default: {} },
    passwordResetToken: String,
    passwordResetExpires: Date,
    fcmToken: String // Added for Firebase Cloud Messaging (FCM) integration
});

const medicationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    type: String,
    dosage: String,
    schedule: { // Advanced schedule schema
        type: String, // 'daily', 'weekly', 'interval', 'one-time'
        time: String, // 'HH:mm' format
        days: [String], // for weekly schedules: ['Monday', 'Tuesday']
        intervalDays: Number, // for interval schedules: 2, 3, 5
        startDate: Date // for interval schedules
    },
    purpose: String,
    side_effects: String,
    instructions: String,
    logs: [{ timestamp: Date }]
});

const exerciseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    schedule: { // Advanced schedule schema
        type: String, // 'daily', 'weekly', 'interval', 'one-time'
        time: String, // 'HH:mm' format
        days: [String], // for weekly schedules: ['Monday', 'Tuesday']
        intervalDays: Number, // for interval schedules: 2, 3, 5
        startDate: Date // for interval schedules
    },
    logs: [{ timestamp: Date }]
});

// New schemas for persistent sessions and conversations
const sessionSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    timestamp: { type: Date, default: Date.now, expires: 3600 } // Session expires in 1 hour
});

const conversationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    history: [{
        role: String,
        parts: [{ text: String }]
    }]
});

const User = mongoose.model('User', userSchema);
const Medication = mongoose.model('Medication', medicationSchema);
const Exercise = mongoose.model('Exercise', exerciseSchema);
const Session = mongoose.model('Session', sessionSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);

// Utility function to get and authenticate user from token
const authenticateUser = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    const token = authHeader.split(' ')[1];

    try {
        const session = await Session.findOne({ token }).populate('userId');
        if (!session) {
            return res.status(401).json({ success: false, message: 'Unauthorized or token expired' });
        }
        req.user = session.userId;
        req.token = token;
        next();
    } catch (err) {
        console.error('Authentication error:', err);
        res.status(500).json({ success: false, message: 'Server error during authentication' });
    }
};

// --- API Routes ---

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// Authentication
app.post('/api/auth/signup', async (req, res) => {
    const { email, password, fullName } = req.body;
    if (!email || !password || !fullName) {
        return res.status(400).json({ success: false, message: 'Missing email, password, or full name' });
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword, fullName });
        await newUser.save();

        const token = randomUUID();
        const newSession = new Session({ userId: newUser._id, token });
        await newSession.save();

        res.status(201).json({ success: true, message: 'User created successfully', token, user: { fullName: newUser.fullName, id: newUser._id } });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ success: false, message: 'Server error during signup' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }
        const token = randomUUID();
        const newSession = new Session({ userId: user._id, token });
        await newSession.save();

        res.json({ success: true, message: 'Login successful', token, user: { fullName: user.fullName, id: user._id } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, message: 'Server error during login' });
    }
});

app.post('/api/auth/forgot_password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const passwordResetToken = randomUUID();
        user.passwordResetToken = passwordResetToken;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        
        console.log(`Password reset token for ${email}: ${passwordResetToken}`);

        res.json({ success: true, message: 'If this email is in our system, a password reset link has been sent.' });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ success: false, message: 'Server error during password reset' });
    }
});

app.post('/api/auth/reset_password', async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const user = await User.findOne({ 
            passwordResetToken: token,
            passwordResetExpires: { $gt: Date.now() }
        });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired token' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();
        res.json({ success: true, message: 'Password has been reset successfully' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ success: false, message: 'Server error during password reset' });
    }
});

app.post('/api/auth/logout', authenticateUser, async (req, res) => {
    try {
        await Session.deleteOne({ token: req.token });
        res.json({ success: true, message: 'Logout successful' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ success: false, message: 'Server error during logout' });
    }
});

// User Management
app.get('/api/user/profile', authenticateUser, (req, res) => {
    const { fullName, email, age, phone, id_number } = req.user;
    const profileData = {
        fullName,
        email,
        age: age || '',
        phone: phone || '',
        id_number: id_number || ''
    };
    res.json({ success: true, profile: profileData });
});

app.put('/api/user/profile', authenticateUser, async (req, res) => {
    const { fullName, age, phone, id_number } = req.body;
    try {
        const updates = {};
        if (fullName) updates.fullName = fullName;
        if (age) updates.age = age;
        if (phone) updates.phone = phone;
        if (id_number) updates.id_number = id_number;

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ success: false, message: 'No data to update' });
        }

        const user = await User.findOneAndUpdate(
            { _id: req.user._id },
            { $set: updates },
            { new: true, runValidators: true }
        );

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ success: true, message: 'Profile updated successfully', profile: { fullName: user.fullName, email: user.email, age: user.age, phone: user.phone, id_number: user.id_number } });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ success: false, message: 'Server error during profile update' });
    }
});

app.put('/api/user/change_password', authenticateUser, async (req, res) => {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
        return res.status(400).json({ success: false, message: 'Missing passwords' });
    }
    try {
        if (!(await bcrypt.compare(current_password, req.user.password))) {
            return res.status(401).json({ success: false, message: 'Incorrect current password' });
        }
        const hashedPassword = await bcrypt.hash(new_password, 10);
        req.user.password = hashedPassword;
        await req.user.save();
        res.json({ success: true, message: 'Password updated successfully' });
    } catch (err) {
        console.error('Change password error:', err);
        res.status(500).json({ success: false, message: 'Server error during password change' });
    }
});

app.put('/api/user/notifications', authenticateUser, async (req, res) => {
    const { notifications } = req.body;
    if (!notifications) {
        return res.status(400).json({ success: false, message: 'Missing notification data' });
    }
    try {
        req.user.notifications = notifications;
        await req.user.save();
        res.json({ success: true, message: 'Notification settings updated' });
    } catch (err) {
        console.error('Notification update error:', err);
        res.status(500).json({ success: false, message: 'Server error during notification update' });
    }
});

app.get('/api/user/report', authenticateUser, async (req, res) => {
    try {
        const userId = req.user._id;
        const medications = await Medication.find({ userId });
        const exercises = await Exercise.find({ userId });
        
        let totalLoggedDoses = 0;
        let totalExpectedDoses = 0;
        
        const oneMonthAgo = new Date();
        oneMonthAgo.setDate(oneMonthAgo.getDate() - 30);

        medications.forEach(med => {
            const loggedDoses = med.logs.filter(log => new Date(log.timestamp) > oneMonthAgo).length;
            totalLoggedDoses += loggedDoses;
            
            const schedule = med.schedule.type.toLowerCase();
            if (schedule === 'daily') {
                totalExpectedDoses += 30; 
            } else if (schedule === 'weekly') {
                totalExpectedDoses += 4; 
            } else if (schedule === 'interval') {
                totalExpectedDoses += Math.floor(30 / med.schedule.intervalDays);
            } else {
                totalExpectedDoses += 30; // Default to daily for unknown schedules
            }
        });

        const adherenceRate = totalExpectedDoses > 0 ? (totalLoggedDoses / totalExpectedDoses) * 100 : 0;
        const missedDoses = totalExpectedDoses - totalLoggedDoses > 0 ? totalExpectedDoses - totalLoggedDoses : 0;
        
        const report = {
            adherence_rate: parseFloat(adherenceRate.toFixed(2)),
            missed_doses: missedDoses,
            on_time_intake: parseFloat((adherenceRate * 0.95).toFixed(2)), 
            medications_tracked: medications.length,
            exercises_tracked: exercises.length
        };

        res.json({ success: true, report });
    } catch (err) {
        console.error('Dynamic report generation error:', err);
        res.status(500).json({ success: false, message: 'Server error while generating report.' });
    }
});

app.put('/api/user/subscription', authenticateUser, async (req, res) => {
    const { plan } = req.body;
    if (!plan) {
        return res.status(400).json({ success: false, message: 'Missing subscription plan' });
    }
    try {
        req.user.subscription = plan;
        await req.user.save();
        res.json({ success: true, message: 'Subscription updated successfully' });
    } catch (err) {
        console.error('Subscription update error:', err);
        res.status(500).json({ success: false, message: 'Server error during subscription update' });
    }
});

app.post('/api/subscription/create-payment-intent', authenticateUser, async (req, res) => {
    const { amount, currency } = req.body;
    try {
        const mockPaymentIntent = { client_secret: 'mock_client_secret_' + randomUUID() };
        res.json({ success: true, clientSecret: mockPaymentIntent.client_secret });
    } catch (e) {
        console.error('Stripe error:', e);
        res.status(500).json({ success: false, message: 'Failed to create payment intent.' });
    }
});

// Medications
app.post('/api/medications', authenticateUser, async (req, res) => {
    const { name, type, dosage, schedule, purpose, side_effects, instructions } = req.body;
    if (!name || !dosage || !schedule) {
        return res.status(400).json({ success: false, message: 'Missing medication details' });
    }
    try {
        const medication = new Medication({
            userId: req.user._id,
            name,
            type,
            dosage,
            schedule,
            purpose,
            side_effects,
            instructions
        });
        await medication.save();
        res.status(201).json({ success: true, message: 'Medication added successfully', medication });
    } catch (err) {
        console.error('Add medication error:', err);
        res.status(500).json({ success: false, message: 'Server error while adding medication' });
    }
});

app.get('/api/medications', authenticateUser, async (req, res) => {
    try {
        const medications = await Medication.find({ userId: req.user._id });
        res.json({ success: true, medications });
    } catch (err) {
        console.error('Get medications error:', err);
        res.status(500).json({ success: false, message: 'Server error while fetching medications' });
    }
});

app.get('/api/medications/:medId', authenticateUser, async (req, res) => {
    const { medId } = req.params;
    try {
        const medication = await Medication.findOne({ _id: medId, userId: req.user._id });
        if (!medication) {
            return res.status(404).json({ success: false, message: 'Medication not found or not owned by user' });
        }
        res.json({ success: true, medication });
    } catch (err) {
        console.error('Get medication error:', err);
        res.status(500).json({ success: false, message: 'Server error while fetching medication' });
    }
});

app.put('/api/medications/:medId', authenticateUser, async (req, res) => {
    const { medId } = req.params;
    const { name, dosage, schedule, purpose, side_effects, instructions } = req.body;
    try {
        const medication = await Medication.findOneAndUpdate(
            { _id: medId, userId: req.user._id },
            { $set: { name, dosage, schedule, purpose, side_effects, instructions } },
            { new: true, runValidators: true }
        );
        if (!medication) {
            return res.status(404).json({ success: false, message: 'Medication not found or not owned by user' });
        }
        res.json({ success: true, message: 'Medication updated successfully', medication });
    } catch (err) {
        console.error('Update medication error:', err);
        res.status(500).json({ success: false, message: 'Server error while updating medication' });
    }
});

app.delete('/api/medications/:medId', authenticateUser, async (req, res) => {
    const { medId } = req.params;
    try {
        const result = await Medication.findOneAndDelete({ _id: medId, userId: req.user._id });
        if (!result) {
            return res.status(404).json({ success: false, message: 'Medication not found or not owned by user' });
        }
        res.json({ success: true, message: 'Medication deleted successfully' });
    } catch (err) {
        console.error('Delete medication error:', err);
        res.status(500).json({ success: false, message: 'Server error while deleting medication' });
    }
});

app.post('/api/medications/:medId/log_dose', authenticateUser, async (req, res) => {
    const { medId } = req.params;
    try {
        const medication = await Medication.findOne({ _id: medId, userId: req.user._id });
        if (!medication) {
            return res.status(404).json({ success: false, message: 'Medication not found or not owned by user' });
        }
        medication.logs.push({ timestamp: new Date() });
        await medication.save();
        res.json({ success: true, message: 'Dose logged successfully' });
    } catch (err) {
        console.error('Log dose error:', err);
        res.status(500).json({ success: false, message: 'Server error while logging dose' });
    }
});

// Exercises
app.post('/api/exercises/reminders', authenticateUser, async (req, res) => {
    const { name, schedule } = req.body;
    if (!name || !schedule) {
        return res.status(400).json({ success: false, message: 'Missing exercise details' });
    }
    try {
        const newExercise = new Exercise({
            userId: req.user._id,
            name,
            schedule
        });
        await newExercise.save();
        res.status(201).json({ success: true, message: 'Exercise reminder added.', exercise: newExercise });
    } catch (err) {
        console.error('Add exercise error:', err);
        res.status(500).json({ success: false, message: 'Server error while adding exercise' });
    }
});

app.get('/api/exercises/reminders', authenticateUser, async (req, res) => {
    try {
        const exercises = await Exercise.find({ userId: req.user._id });
        res.json({ success: true, exercises });
    } catch (err) {
        console.error('Get exercises error:', err);
        res.status(500).json({ success: false, message: 'Server error while fetching exercises' });
    }
});

// New routes for updating and deleting exercises and logging sessions
app.put('/api/exercises/reminders/:exerciseId', authenticateUser, async (req, res) => {
    const { exerciseId } = req.params;
    const { name, schedule } = req.body;
    try {
        const exercise = await Exercise.findOneAndUpdate(
            { _id: exerciseId, userId: req.user._id },
            { $set: { name, schedule } },
            { new: true, runValidators: true }
        );
        if (!exercise) {
            return res.status(404).json({ success: false, message: 'Exercise not found or not owned by user' });
        }
        res.json({ success: true, message: 'Exercise updated successfully', exercise });
    } catch (err) {
        console.error('Update exercise error:', err);
        res.status(500).json({ success: false, message: 'Server error while updating exercise' });
    }
});

app.delete('/api/exercises/reminders/:exerciseId', authenticateUser, async (req, res) => {
    const { exerciseId } = req.params;
    try {
        const result = await Exercise.findOneAndDelete({ _id: exerciseId, userId: req.user._id });
        if (!result) {
            return res.status(404).json({ success: false, message: 'Exercise not found or not owned by user' });
        }
        res.json({ success: true, message: 'Exercise deleted successfully' });
    } catch (err) {
        console.error('Delete exercise error:', err);
        res.status(500).json({ success: false, message: 'Server error while deleting exercise' });
    }
});

app.post('/api/exercises/:exerciseId/log_session', authenticateUser, async (req, res) => {
    const { exerciseId } = req.params;
    try {
        const exercise = await Exercise.findOne({ _id: exerciseId, userId: req.user._id });
        if (!exercise) {
            return res.status(404).json({ success: false, message: 'Exercise not found or not owned by user' });
        }
        exercise.logs.push({ timestamp: new Date() });
        await exercise.save();
        res.json({ success: true, message: 'Exercise session logged successfully' });
    } catch (err) {
        console.error('Log exercise session error:', err);
        res.status(500).json({ success: false, message: 'Server error while logging exercise session' });
    }
});

app.get('/api/calendar/events', authenticateUser, async (req, res) => {
    try {
        const medications = await Medication.find({ userId: req.user._id });
        const exercises = await Exercise.find({ userId: req.user._id });
        const events = [
            ...medications.map(med => ({ type: 'medication', name: med.name, schedule: med.schedule })),
            ...exercises.map(ex => ({ type: 'exercise', name: ex.name, schedule: ex.schedule }))
        ];
        res.json({ success: true, events });
    } catch (err) {
        console.error('Calendar events error:', err);
        res.status(500).json({ success: false, message: 'Server error while fetching calendar events' });
    }
});

// AI Assistant
const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=";
const GEMINI_TTS_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-tts:generateContent?key=";
const GEMINI_VISION_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=";

app.post('/api/ai_assistant', authenticateUser, async (req, res) => {
    const userMessage = req.body.message;
    if (!userMessage) {
        return res.status(400).json({ success: false, message: 'Missing message' });
    }

    try {
        const conversation = await Conversation.findOne({ userId: req.user._id });
        let chatHistory = conversation ? conversation.history : [];

        chatHistory.push({ role: 'user', parts: [{ text: userMessage }] });

        const payload = {
            contents: chatHistory,
            systemInstruction: {
                parts: [{ text: "You are a helpful and compassionate health AI assistant. Your purpose is to provide general, non-diagnostic information related to health and wellness. Do not give medical advice. Encourage the user to consult with a healthcare professional." }]
            }
        };

        const response = await axios.post(`${GEMINI_API_URL}${API_KEY}`, payload);
        const aiResponseText = response.data.candidates[0].content.parts[0].text;
        chatHistory.push({ role: 'model', parts: [{ text: aiResponseText }] });

        if (conversation) {
            conversation.history = chatHistory;
            await conversation.save();
        } else {
            const newConversation = new Conversation({ userId: req.user._id, history: chatHistory });
            await newConversation.save();
        }

        res.json({ success: true, response: aiResponseText });
    } catch (e) {
        console.error('AI API call failed:', e.response?.data || e.message);
        res.status(500).json({ success: false, message: 'Failed to get a response from the AI assistant.' });
    }
});

app.post('/api/tts', authenticateUser, async (req, res) => {
    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ success: false, message: 'Missing text' });
    }
    const payload = {
        contents: [{ parts: [{ text }] }],
        generationConfig: {
            responseModalities: ['AUDIO'],
            speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: 'Puck' } } }
        },
        model: 'gemini-2.5-flash-preview-tts'
    };
    try {
        const response = await axios.post(`${GEMINI_TTS_API_URL}${API_KEY}`, payload);
        const audioData = response.data.candidates[0].content.parts[0].inlineData.data;
        res.json({ success: true, audio_data: audioData });
    } catch (e) {
        console.error('TTS API call failed:', e.response?.data || e.message);
        res.status(500).json({ success: false, message: 'Failed to generate audio.' });
    }
});

app.post('/api/medications/scan', authenticateUser, async (req, res) => {
    const { imageData } = req.body;
    if (!imageData) {
        return res.status(400).json({ success: false, message: 'No image data provided' });
    }
    const payload = {
        contents: [{
            parts: [{
                text: "Analyze this image of a medication bottle. Identify the medication name, dosage, and any relevant instructions or side effects on the label. Provide the extracted information in a structured JSON format."
            }, {
                inlineData: {
                    mimeType: "image/jpeg",
                    data: imageData
                }
            }]
        }],
        generationConfig: {
            responseMimeType: "application/json"
        }
    };
    
    try {
        const response = await axios.post(`${GEMINI_VISION_API_URL}${API_KEY}`, payload);
        const recognizedData = JSON.parse(response.data.candidates[0].content.parts[0].text);
        res.json({ success: true, medication: recognizedData });
    } catch (e) {
        console.error('Gemini Vision API call failed:', e.response?.data || e.message);
        res.status(500).json({ success: false, message: 'Failed to process image with AI.' });
    }
});

app.post('/api/medications/scan-and-add', authenticateUser, async (req, res) => {
    const { imageData } = req.body;
    if (!imageData) {
        return res.status(400).json({ success: false, message: 'No image data provided' });
    }
    const payload = {
        contents: [{
            parts: [{
                text: "Analyze this image of a medication bottle. Identify the medication name, dosage, schedule, purpose, side effects, and instructions on the label. Provide the extracted information in a structured JSON format. The schedule should be an object with properties for type (e.g., 'daily'), time (e.g., 'HH:mm'), and optional properties like days for a weekly schedule. The purpose, side effects, and instructions should be strings. Fill in with 'N/A' if information is not found. Example: { \"name\": \"Ibuprofen\", \"dosage\": \"200mg\", \"schedule\": {\"type\": \"daily\", \"time\": \"08:00\"}, \"purpose\": \"Pain relief\", \"side_effects\": \"Dizziness, nausea\", \"instructions\": \"Take with food\" }."
            }, {
                inlineData: {
                    mimeType: "image/jpeg",
                    data: imageData
                }
            }]
        }],
        generationConfig: {
            responseMimeType: "application/json",
            responseSchema: {
                type: "OBJECT",
                properties: {
                    "name": { "type": "STRING" },
                    "dosage": { "type": "STRING" },
                    "schedule": {
                        "type": "OBJECT",
                        "properties": {
                            "type": { "type": "STRING" },
                            "time": { "type": "STRING" },
                            "days": { "type": "ARRAY", "items": { "type": "STRING" } },
                            "intervalDays": { "type": "NUMBER" },
                            "startDate": { "type": "STRING" }
                        }
                    },
                    "purpose": { "type": "STRING" },
                    "side_effects": { "type": "STRING" },
                    "instructions": { "type": "STRING" }
                }
            }
        }
    };

    try {
        const response = await axios.post(`${GEMINI_VISION_API_URL}${API_KEY}`, payload);
        const rawResponse = response.data.candidates[0].content.parts[0].text;
        let recognizedData;
        try {
            recognizedData = JSON.parse(rawResponse);
        } catch (parseError) {
            console.error('Failed to parse JSON from AI response:', rawResponse);
            return res.status(500).json({ success: false, message: 'Failed to process AI response due to a formatting error.' });
        }
        
        // Ensure schedule is in the correct format before creating the document
        if (typeof recognizedData.schedule === 'string') {
            const [time] = recognizedData.schedule.split(' ');
            recognizedData.schedule = { type: 'daily', time: time || '08:00' };
        } else {
             // Handle cases where time is not a string
             if (recognizedData.schedule && typeof recognizedData.schedule.time !== 'string') {
                recognizedData.schedule.time = '08:00';
            }
        }

        const newMedication = new Medication({
            userId: req.user._id,
            name: recognizedData.name || 'N/A',
            dosage: recognizedData.dosage || 'N/A',
            schedule: recognizedData.schedule || { type: 'daily', time: '08:00' },
            purpose: recognizedData.purpose || 'N/A',
            side_effects: recognizedData.side_effects || 'N/A',
            instructions: recognizedData.instructions || 'N/A'
        });
        await newMedication.save();
        
        res.status(201).json({ success: true, message: 'Medication scanned and added successfully.', medication: newMedication });

    } catch (e) {
        console.error('Image scan API call failed:', e.response?.data || e.message);
        res.status(500).json({ success: false, message: 'Failed to process image with AI and save to database.' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// A real-world placeholder for sending notifications via Twilio
const sendNotification = async (user, title, body, type) => {
    if (user.phone && user.notifications.reminderAlerts) {
        try {
            await twilioClient.messages.create({
                body: `${title} - ${body}`,
                to: user.phone,
                from: TWILIO_PHONE_NUMBER
            });
            console.log(`Twilio SMS sent to ${user.email}`);
        } catch (error) {
            console.error(`Failed to send SMS to ${user.email}:`, error.message);
        }
    }
};

/**
 * Checks if a scheduled item is due based on the current time and its schedule.
 * @param {object} schedule - The schedule object from the database.
 * @returns {boolean} - True if the item is due, otherwise false.
 */
const isDue = (schedule) => {
    const now = new Date();
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();

    if (!schedule || !schedule.time) {
        return false;
    }
    const [scheduledHour, scheduledMinute] = schedule.time.split(':').map(Number);
    if (currentHour !== scheduledHour || currentMinute !== scheduledMinute) {
        return false;
    }

    switch (schedule.type) {
        case 'daily':
            return true;
        case 'weekly':
            // The days of the week are stored as strings, e.g., 'Sunday', 'Monday'.
            const daysOfWeek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
            const currentDay = daysOfWeek[now.getDay()];
            return schedule.days && schedule.days.includes(currentDay);
        case 'interval':
            // Check if it's the correct day based on the interval and start date.
            if (!schedule.startDate || !schedule.intervalDays) return false;
            const startDate = parseISO(schedule.startDate);
            const diffInDays = Math.floor((now - startDate) / (1000 * 60 * 60 * 24));
            return diffInDays % schedule.intervalDays === 0 && isSameDay(now, new Date(now.getFullYear(), now.getMonth(), now.getDate()));
        case 'one-time':
            // Check if it's the specific date and time for a one-time event.
            if (!schedule.startDate) return false;
            const scheduledDate = parseISO(schedule.startDate);
            return isSameDay(now, scheduledDate);
        default:
            return false;
    }
};

// Cron job to check for reminders every minute
schedule.scheduleJob('* * * * *', async () => {
    console.log('Running reminder cron job...');
    try {
        const users = await User.find({ 'notifications.reminderAlerts': true });

        for (const user of users) {
            // Check for medication reminders
            const userMeds = await Medication.find({ userId: user._id });
            for (const medication of userMeds) {
                if (medication.schedule && isDue(medication.schedule)) {
                    const title = `Time to take your medication: ${medication.name}`;
                    const body = medication.instructions || 'Remember to take your dose as instructed.';
                    sendNotification(user, title, body, 'medication');
                }
            }

            // Check for exercise reminders
            const userExercises = await Exercise.find({ userId: user._id });
            for (const exercise of userExercises) {
                if (exercise.schedule && isDue(exercise.schedule)) {
                    const title = `Time for your exercise: ${exercise.name}`;
                    const body = 'Your scheduled workout is now due!';
                    sendNotification(user, title, body, 'exercise');
                }
            }
        }
    } catch (err) {
        console.error('Cron job failed:', err);
    }
});
