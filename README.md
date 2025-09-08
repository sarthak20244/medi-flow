# Project Report

## Server Overview
The `server.js` file provides the full backend for the health application. Unlike a simple in-memory server, this version uses **MongoDB with Mongoose** for persistent data storage, making the application fully dynamic. All user data, medications, exercises, and AI conversations are now stored in a database, so information is saved between sessions and accessible from any device.

---

## Core Components

### Express & Middleware
- The server is built with **Express.js**.
- Uses **cors** to allow requests from different origins.
- Uses `express.json()` to parse JSON request bodies.

### MongoDB & Mongoose
- Connects to MongoDB for storing all application data.
- Uses **Mongoose ODM** for structured schemas.

### Database Schemas
- **User**: email, password (hashed), fullName, age, phone, id_number, subscription status, notification settings, reset tokens.
- **Medication**: name, dosage, schedule, log of taken doses.
- **Exercise**: exercise reminders (name, schedule).
- **Session**: manages active sessions & authentication tokens.
- **Conversation**: stores AI chat history for persistent conversations.

### Authentication Middleware
- `authenticateUser`: validates tokens against the Session collection.
- Attaches user data to the request if valid.

---

## API Endpoints

### 1. Authentication (`/api/auth`)

| Endpoint | Method | Functionality |
|----------|--------|---------------|
| `/api/auth/signup` | POST | Create user with hashed password, generate session token. |
| `/api/auth/login` | POST | Authenticate user, return session token. |
| `/api/auth/forgot_password` | POST | Generate password reset token (placeholder, no email). |
| `/api/auth/reset_password` | POST | Validate reset token, update hashed password. |
| `/api/auth/logout` | POST | Delete session, log user out. |

---

### 2. User Management (`/api/user`)

| Endpoint | Method | Functionality |
|----------|--------|---------------|
| `/api/user/profile` | GET | Fetch user profile. |
| `/api/user/profile` | PUT | Update profile fields. |
| `/api/user/change_password` | PUT | Verify and update password. |
| `/api/user/notifications` | PUT | Update notification preferences. |
| `/api/user/subscription` | PUT | Update subscription status. |
| `/api/subscription/create-payment-intent` | POST | Mock payment intent (Stripe placeholder). |

---

### 3. Medications (`/api/medications`)

| Endpoint | Method | Functionality |
|----------|--------|---------------|
| `/api/medications` | POST | Add medication for user. |
| `/api/medications` | GET | Get all medications. |
| `/api/medications/:medId` | GET | Get medication by ID. |
| `/api/medications/:medId` | PUT | Update medication details. |
| `/api/medications/:medId` | DELETE | Delete medication. |
| `/api/medications/:medId/log_dose` | POST | Log taken dose (timestamp). |
| `/api/medications/scan` | POST | Analyze medication bottle via **Gemini Vision API**. |

---

### 4. Exercises (`/api/exercises`)

| Endpoint | Method | Functionality |
|----------|--------|---------------|
| `/api/exercises/reminders` | POST | Add exercise reminder. |
| `/api/exercises/reminders` | GET | Fetch exercise reminders. |

---

### 5. AI Assistant (`/api/ai_assistant` & `/api/tts`)

| Endpoint | Method | Functionality |
|----------|--------|---------------|
| `/api/ai_assistant` | POST | Send message to Gemini API, store conversation history. |
| `/api/tts` | POST | Convert text to audio via **Gemini TTS API** (base64 encoded). |

---

## Current Limitations
- **Payment Integration**: Stripe is mocked. Needs webhook for real payments.
- **Email Sending**: Forgot Password does not send actual reset email.

---

## Table of Contents
- [Server Overview](#server-overview)  
- [Core Components](#core-components)  
- [API Endpoints](#api-endpoints)  
  - [Authentication](#1-authentication-apiauth)  
  - [User Management](#2-user-management-apiuser)  
  - [Medications](#3-medications-apimedications)  
  - [Exercises](#4-exercises-apiexercises)  
  - [AI Assistant](#5-ai-assistant-apia_assistant--apitts)  
- [Current Limitations](#current-limitations)
