const express = require('express');
const cors = require('cors');
require('dotenv').config();
const stripe = require('stripe')(process.env.PAYMENT_GATEWAY_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());

const serviceAccount = require("./firebase-admin-key.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// Database connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.kbhlw7l.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

// Database collections
let db, userCollection, parcelCollection, paymentsCollection, ridersCollection, trackingCollection;

async function connectDB() {
    try {
        // await client.connect();
        db = client.db('parcelDB');
        userCollection = db.collection('users')
        parcelCollection = db.collection('parcels');
        paymentsCollection = db.collection('payments');
        ridersCollection = db.collection('riders');
        trackingCollection = db.collection('tracking');

        // Create indexes
        await parcelCollection.createIndex({ trackingNumber: 1 });
        await parcelCollection.createIndex({ userEmail: 1 });
        await paymentsCollection.createIndex({ transactionId: 1 });
        await ridersCollection.createIndex({ email: 1 });
        await ridersCollection.createIndex({ status: 1 });

        await db.command({ ping: 1 });
        console.log("✅ Connected to MongoDB!");
    } catch (error) {
        console.error("❌ MongoDB connection failed:", error);
    }
}
connectDB();

// custom middleware
const verifyFBToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
    }

    // verify token
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
    }
    catch (error) {
        return res.status(403).send({ message: 'forbidden access' });
    }
}

// Helper middleware for error handling
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Routes
app.get('/', (req, res) => {
    res.send('📦 Parcel Tracking Server is Running');
});

// User routes
app.post('/users', async (req, res) => {
    const email = req.body.email;
    const userExists = await userCollection.findOne({ email });
    if (userExists) {
        return res.status(200).send({
            message: 'user already exist',
            inserted: false
        });
    }

    const user = req.body;
    const result = await userCollection.insertOne(user);
    res.send(result);
});

// Parcel routes
app.get('/parcels', verifyFBToken, asyncHandler(async (req, res) => {
    const { email } = req.query;

    const filter = email ? { userEmail: email } : {};

    const parcels = await parcelCollection.find(filter)
        .sort({ _id: -1 })
        .toArray();

    res.json(parcels);
}));

app.get('/parcels/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid parcel ID' });
    }

    const parcel = await parcelCollection.findOne({ _id: new ObjectId(id) });
    if (!parcel) {
        return res.status(404).json({ message: 'Parcel not found' });
    }

    res.json(parcel);
}));

app.post('/parcels', asyncHandler(async (req, res) => {
    const newParcel = req.body;

    // Basic validation
    if (!newParcel.userEmail || !newParcel.trackingNumber) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    const result = await parcelCollection.insertOne(newParcel);
    res.status(201).json(result);
}));

app.delete('/parcels/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid parcel ID' });
    }

    const result = await parcelCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
        return res.status(404).json({ message: 'Parcel not found' });
    }

    res.json({ message: 'Parcel deleted successfully' });
}));

// Rider routes - Updated and improved
app.get('/riders/pending', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const pendingRiders = await ridersCollection.find({ status: "pending" })
            .sort({ createdAt: -1 })
            .toArray();

        res.json({
            success: true,
            data: pendingRiders
        });
    } catch (error) {
        console.error('Error fetching pending riders:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending riders'
        });
    }
}));

app.get('/riders/active', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const { search } = req.query;
        let query = { status: 'active' };

        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } }
            ];
        }

        const activeRiders = await ridersCollection.find(query)
            .sort({ updatedAt: -1 })
            .toArray();

        res.json({
            success: true,
            data: activeRiders
        });
    } catch (error) {
        console.error('Error fetching active riders:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch active riders'
        });
    }
}));

app.post('/riders', asyncHandler(async (req, res) => {
    try {
        const rider = req.body;

        // Check if rider already exists
        // const existingRider = await ridersCollection.findOne({ 
        //     $or: [
        //         { email: rider.email },
        //         { phone: rider.phone }
        //     ]
        // });

        // if (existingRider) {
        //     return res.status(400).json({
        //         success: false,
        //         message: 'Rider with this email or phone already exists'
        //     });
        // }

        // Set default status and timestamps
        const newRider = {
            ...rider,
            status: "pending",
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const result = await ridersCollection.insertOne(newRider);

        res.status(201).json({
            success: true,
            message: 'Rider application submitted successfully',
            data: {
                insertedId: result.insertedId,
                status: newRider.status
            }
        });
    } catch (error) {
        console.error('Error creating rider:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit rider application'
        });
    }
}));

app.get('/riders/:id', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        const rider = await ridersCollection.findOne({ _id: new ObjectId(id) });

        if (!rider) {
            return res.status(404).json({
                success: false,
                message: "Rider not found"
            });
        }

        res.json({
            success: true,
            data: rider
        });
    } catch (error) {
        console.error('Error fetching rider:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch rider details'
        });
    }
}));

app.put('/riders/:id/approve', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        const result = await ridersCollection.updateOne(
            { _id: new ObjectId(id), status: 'pending' },
            {
                $set: {
                    status: "active",
                    updatedAt: new Date()
                }
            }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({
                success: false,
                message: "Rider not found or already processed"
            });
        }

        res.json({
            success: true,
            message: "Rider approved successfully",
            data: {
                status: 'active'
            }
        });
    } catch (error) {
        console.error('Error approving rider:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve rider'
        });
    }
}));

app.put('/riders/:id/reject', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        const result = await ridersCollection.updateOne(
            { _id: new ObjectId(id), status: 'pending' },
            {
                $set: {
                    status: "rejected",
                    updatedAt: new Date()
                }
            }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({
                success: false,
                message: "Rider not found or already processed"
            });
        }

        res.json({
            success: true,
            message: "Rider rejected successfully",
            data: {
                status: 'rejected'
            }
        });
    } catch (error) {
        console.error('Error rejecting rider:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject rider'
        });
    }
}));










app.patch('/riders/:id/status', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;
        const { status, email } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        // Validate status
        const validStatuses = ['active', 'inactive', 'deactivated'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status value. Allowed values: active, inactive, deactivated'
            });
        }

        // Update rider's status
        const riderResult = await ridersCollection.updateOne(
            { _id: new ObjectId(id) },
            {
                $set: {
                    status: status,
                    updatedAt: new Date()
                }
            }
        );

        if (riderResult.modifiedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Rider not found or status unchanged'
            });
        }

        // If rider is activated, update user role to 'rider'
        if (status === 'active' && email) {
            const userResult = await userCollection.updateOne(
                { email: { $regex: `^${email.trim()}$`, $options: 'i' } }, // case-insensitive match
                {
                    $set: { role: 'rider' }
                }
            );

            console.log('User role update result:', userResult);

            if (userResult.matchedCount === 0) {
                console.warn('No matching user found for email:', email);
            }
        }

        // Send success response
        res.json({
            success: true,
            message: `Rider status updated to ${status} successfully`,
            data: { status }
        });

    } catch (error) {
        console.error('Error updating rider status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update rider status'
        });
    }
}));















app.delete('/riders/:id', verifyFBToken, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        const result = await ridersCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: "Rider not found"
            });
        }

        res.json({
            success: true,
            message: "Rider deleted successfully"
        });
    } catch (error) {
        console.error('Error deleting rider:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete rider'
        });
    }
}));

// Tracking routes
app.post('/tracking', verifyFBToken, asyncHandler(async (req, res) => {
    const { tracking_id, parcel_id, status, message, update_by = '' } = req.body;

    const log = {
        tracking_id,
        parcel_id: parcel_id ? new ObjectId(parcel_id) : undefined,
        status,
        message,
        time: new Date(),
        update_by,
    };
    const result = await trackingCollection.insertOne(log);
    res.send({ success: true, insertedId: result.insertedId });
}));

// Payment routes
app.get('/payments', verifyFBToken, asyncHandler(async (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ message: 'Email parameter is required' });
    }

    // Verify the requesting user owns this data
    if (req.decoded.email !== email) {
        return res.status(403).send({ message: 'forbidden access' });
    }

    const history = await paymentsCollection.find({ userEmail: email })
        .sort({ paid_at: -1 })
        .toArray();

    res.json(history);
}));

app.post('/payments', verifyFBToken, asyncHandler(async (req, res) => {
    const { parcelId, trackingNumber, amount, userEmail, paymentMethod, transactionId } = req.body;

    // Validate required fields
    if (!parcelId || !trackingNumber || !amount || !userEmail || !transactionId) {
        return res.status(400).json({
            success: false,
            message: 'Missing required payment fields'
        });
    }

    const session = client.startSession();
    try {
        await session.withTransaction(async () => {
            // 1. Save payment record
            const payment = {
                parcelId: new ObjectId(parcelId),
                trackingNumber,
                userEmail,
                amount,
                paymentMethod,
                transactionId,
                status: "Success",
                paid_at: new Date()
            };

            const paymentResult = await paymentsCollection.insertOne(payment, { session });

            // 2. Update parcel status
            const updateResult = await parcelCollection.updateOne(
                { _id: new ObjectId(parcelId), trackingNumber },
                {
                    $set: {
                        paymentStatus: "Paid",
                        paidAt: payment.paid_at,
                        status: "Processing"
                    }
                },
                { session }
            );

            if (updateResult.modifiedCount === 0) {
                throw new Error('Failed to update parcel status');
            }

            res.json({
                success: true,
                message: 'Payment processed successfully',
                paymentId: paymentResult.insertedId
            });
        });
    } catch (error) {
        console.error('Payment transaction failed:', error);
        res.status(500).json({
            success: false,
            message: 'Payment processing failed',
            error: error.message
        });
    } finally {
        await session.endSession();
    }
}));





// update profile 
// Get user by email
app.get('/users/:email', verifyFBToken, async (req, res) => {
    try {
        const { email } = req.params;

        const user = await userCollection.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Remove sensitive data before sending
        const { password, ...userData } = user;

        res.json({
            success: true,
            data: userData
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user data'
        });
    }
});

// Update user profile
app.put('/users/update', verifyFBToken, async (req, res) => {
    try {
        const { email, updates } = req.body;

        // Verify the requesting user can only update their own profile
        if (req.decoded.email !== email) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized to update this profile'
            });
        }

        // Prepare update data
        const updateData = {
            name: updates.name,
            phone: updates.phone,
            address: updates.address,
            photoURL: updates.photoURL,
            updatedAt: new Date().toISOString()
        };

        const result = await userCollection.updateOne(
            { email },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Get updated user data to return
        const updatedUser = await userCollection.findOne({ email });
        const { password, ...userData } = updatedUser;

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: userData
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile'
        });
    }
});










app.post('/create-payment-intent', verifyFBToken, asyncHandler(async (req, res) => {
    const { amountCents, parcelId } = req.body;

    if (!amountCents || !parcelId) {
        return res.status(400).json({ error: 'Amount and parcel ID are required' });
    }

    const paymentIntent = await stripe.paymentIntents.create({
        amount: parseInt(amountCents),
        currency: 'usd',
        metadata: { parcelId }
    });

    res.json({
        clientSecret: paymentIntent.client_secret,
        paymentIntentId: paymentIntent.id
    });
}));



// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Start server
app.listen(port, () => {
    console.log(`🚀 Server is running on http://localhost:${port}`);
});

