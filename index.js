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


const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')

const serviceAccount = JSON.parse(decodedKey)

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
        userCollection = db.collection('users');
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
        // In case of connection failure, try to reconnect
        setTimeout(connectDB, 5000);
    }
}

// Start the server only after DB connection is established
async function startServer() {
    try {
        await connectDB();
        app.listen(port, () => {
            console.log(`🚀 Server is running on http://localhost:${port}`);
        });
    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
}

// Custom middleware
const verifyFBToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
    }

    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
    } catch (error) {
        return res.status(403).send({ message: 'forbidden access' });
    }
};

const verifyAdmin = async (req, res, next) => {
    const email = req.decoded.email;
    const query = { email };
    const user = await userCollection.findOne(query);
    if (!user || user.role !== 'admin') {
        return res.status(403).send({ message: 'forbidden access' });
    }
    next();
};

const verifyRider = async (req, res, next) => {
    const email = req.decoded.email;
    const query = { email };
    const user = await userCollection.findOne(query);
    if (!user || user.role !== 'rider') {
        return res.status(403).send({ message: 'forbidden access' });
    }
    next();
};

const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Helper function for default locations
function getDefaultLocation(status) {
    const locationMap = {
        order_confirmed: 'China',
        quality_inspection: 'China',
        passed_inspection: 'China',
        packed_for_warehouse: 'China',
        arrived_at_warehouse: 'Foreign Trade Warehouse (China)',
        awaiting_departure: 'Foreign Trade Warehouse (China)',
        international_shipping: 'In Transit (International)',
        arrived_at_customs: 'Destination Customs',
        clearance_finished: 'Local Warehouse',
        arrived_at_local_warehouse: 'Local Warehouse',
        local_quality_check: 'Local Warehouse',
        awaiting_courier: 'Local Warehouse',
        in_transit: 'Local Delivery',
        delivered: 'Delivered to Recipient',
        cancelled: 'Cancelled'
    };
    return locationMap[status] || 'Unknown Location';
}

// Routes
app.get('/', (req, res) => {
    res.send('📦 Parcel Tracking Server is Running');
});

// User routes
app.get('/users/role/:email', verifyFBToken, async (req, res) => {
    try {
        const email = req.params.email;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        if (req.decoded.email !== email) {
            return res.status(403).json({ message: 'Unauthorized access' });
        }

        const user = await userCollection.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            role: user.role || 'user',
            email: user.email
        });
    } catch (error) {
        console.error('Error getting user role:', error);
        res.status(500).json({ message: 'Failed to get role', error: error.message });
    }
});

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

app.put('/users/update', verifyFBToken, async (req, res) => {
    try {
        const { email, updates } = req.body;

        if (req.decoded.email !== email) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized to update this profile'
            });
        }

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

app.patch('/parcels/:id/assign', verifyFBToken, asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { riderId, riderName, riderPhone, status, deliveryStatus } = req.body;

    if (!ObjectId.isValid(id) || !ObjectId.isValid(riderId)) {
        return res.status(400).json({ message: 'Invalid ID(s)' });
    }

    const session = client.startSession();
    try {
        await session.withTransaction(async () => {
            const parcelUpdate = await parcelCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        assigned_rider_id: new ObjectId(riderId),
                        assigned_rider_name: riderName,
                        assigned_rider_phone: riderPhone,
                        status: status || 'assigned',
                        updatedAt: new Date().toISOString()
                    },
                    $push: {
                        deliveryStatus: deliveryStatus || {
                            status: 'in_transit',
                            date: new Date().toISOString(),
                            location: 'Warehouse',
                            details: `Assigned to rider ${riderName}`,
                            changedBy: req.decoded.email || 'system'
                        }
                    }
                },
                { session }
            );

            if (parcelUpdate.modifiedCount === 0) {
                throw new Error('Parcel not found or update failed');
            }

            await ridersCollection.updateOne(
                { _id: new ObjectId(riderId) },
                {
                    $set: {
                        status: 'active',
                        work_status: 'in_delivery',
                        updatedAt: new Date().toISOString()
                    }
                },
                { session }
            );

            res.json({
                success: true,
                message: 'Rider assigned successfully'
            });
        });
    } catch (error) {
        console.error('Assignment transaction failed:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to assign rider',
            error: error.message
        });
    } finally {
        await session.endSession();
    }
}));

app.patch('/parcels/:id/status', verifyFBToken, asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status, location, details, changedBy } = req.body;

    if (!ObjectId.isValid(id)) {
        return res.status(400).json({ 
            success: false,
            message: 'Invalid parcel ID format'
        });
    }

    const validStatuses = [
        'order_confirmed', 'quality_inspection', 'passed_inspection',
        'packed_for_warehouse', 'arrived_at_warehouse', 'awaiting_departure',
        'international_shipping', 'arrived_at_customs', 'clearance_finished',
        'arrived_at_local_warehouse', 'local_quality_check', 'awaiting_courier',
        'in_transit', 'delivered', 'cancelled'
    ];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ 
            success: false,
            message: 'Invalid status value',
            validStatuses
        });
    }

    try {
        const statusUpdate = {
            status,
            date: new Date().toISOString(),
            location: location || getDefaultLocation(status),
            details: details || `Status changed to ${status.replace(/_/g, ' ')}`,
            changedBy: changedBy || 'admin'
        };

        const parcel = await parcelCollection.findOne({ _id: new ObjectId(id) });
        if (!parcel) {
            return res.status(404).json({ 
                success: false,
                message: 'Parcel not found'
            });
        }

        const updateOperation = {
            $set: {
                status: status,
                updatedAt: new Date().toISOString()
            },
            $push: {
                deliveryStatus: statusUpdate
            }
        };

        const result = await parcelCollection.updateOne(
            { _id: new ObjectId(id) },
            updateOperation
        );

        if (result.modifiedCount === 0) {
            return res.status(400).json({
                success: false,
                message: 'No documents were modified'
            });
        }

        if (status === 'delivered' && parcel.assigned_rider_id) {
            await ridersCollection.updateOne(
                { _id: parcel.assigned_rider_id },
                { $set: { work_status: 'available' } }
            );
        }

        res.json({
            success: true,
            message: 'Parcel status updated successfully',
            data: statusUpdate,
            modifiedCount: result.modifiedCount
        });
    } catch (error) {
        console.error('[STATUS UPDATE ERROR]', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update status',
            error: error.message
        });
    }
}));

app.patch('/parcels/:id/assign-rider', verifyFBToken, asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { riderId, riderName, riderPhone } = req.body;

    if (!ObjectId.isValid(id) || !ObjectId.isValid(riderId)) {
        return res.status(400).json({ message: 'Invalid ID(s)' });
    }

    const session = client.startSession();
    try {
        await session.withTransaction(async () => {
            const parcelUpdate = await parcelCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        assigned_rider_id: new ObjectId(riderId),
                        assigned_rider_name: riderName,
                        assigned_rider_phone: riderPhone,
                        updatedAt: new Date().toISOString()
                    },
                    $push: {
                        deliveryStatus: {
                            status: 'in_transit',
                            date: new Date().toISOString(),
                            location: 'Warehouse',
                            details: `Assigned to rider ${riderName}`,
                            changedBy: req.decoded.email || 'system'
                        }
                    }
                },
                { session }
            );

            if (parcelUpdate.modifiedCount === 0) {
                throw new Error('Parcel not found or update failed');
            }

            await ridersCollection.updateOne(
                { _id: new ObjectId(riderId) },
                {
                    $set: {
                        work_status: 'in_delivery',
                        updatedAt: new Date().toISOString()
                    }
                },
                { session }
            );

            res.json({
                success: true,
                message: 'Rider assigned successfully'
            });
        });
    } catch (error) {
        console.error('Assignment transaction failed:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to assign rider',
            error: error.message
        });
    } finally {
        await session.endSession();
    }
}));

// Rider routes
app.get('/riders/available', verifyFBToken, asyncHandler(async (req, res) => {
    const { district, search } = req.query;
    try {
        const query = {
            status: 'active',
            work_status: 'available'
        };

        if (district) {
            query.district = district;
        }

        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } }
            ];
        }

        const riders = await ridersCollection.find(query)
            .project({
                name: 1,
                email: 1,
                phone: 1,
                district: 1,
                vehicleType: 1,
                vehicleNumber: 1,
                status: 1,
                work_status: 1
            })
            .sort({ name: 1 })
            .toArray();

        res.json({
            success: true,
            data: riders
        });
    } catch (error) {
        console.error('Error fetching available riders:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch available riders'
        });
    }
}));

app.get('/parcels/assignable', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
    try {
        const parcels = await parcelCollection.aggregate([
            {
                $match: {
                    paymentStatus: 'Paid',
                    $or: [
                        { 'deliveryStatus.status': { $exists: false } },
                        { 'deliveryStatus.status': { $nin: ['delivered', 'cancelled'] } }
                    ]
                }
            },
            {
                $lookup: {
                    from: 'riders',
                    localField: 'assigned_rider_id',
                    foreignField: '_id',
                    as: 'rider'
                }
            },
            {
                $unwind: {
                    path: '$rider',
                    preserveNullAndEmptyArrays: true
                }
            },
            {
                $sort: { createdAt: 1 }
            }
        ]).toArray();

        res.json({
            success: true,
            data: parcels
        });
    } catch (error) {
        console.error('Error fetching assignable parcels:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch assignable parcels'
        });
    }
}));

app.get('/riders/pending', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
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

app.get('/riders/active', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
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

app.get('/riders/:id', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
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

app.put('/riders/:id/approve', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;
        const { email } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        const session = client.startSession();
        let result;

        try {
            await session.withTransaction(async () => {
                const riderResult = await ridersCollection.updateOne(
                    { _id: new ObjectId(id), status: 'pending' },
                    {
                        $set: {
                            status: "active",
                            updatedAt: new Date()
                        }
                    },
                    { session }
                );

                if (riderResult.modifiedCount === 0) {
                    throw new Error("Rider not found or already processed");
                }

                if (email) {
                    const userResult = await userCollection.updateOne(
                        { email: email },
                        {
                            $set: {
                                role: 'rider',
                                updatedAt: new Date().toISOString()
                            }
                        },
                        { session }
                    );

                    if (userResult.matchedCount === 0) {
                        console.warn(`No user found with email: ${email}`);
                    }
                }
            });

            result = {
                success: true,
                message: "Rider approved and user role updated successfully",
                data: {
                    status: 'active'
                }
            };
        } finally {
            await session.endSession();
        }

        res.json(result);
    } catch (error) {
        console.error('Error approving rider:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve rider',
            error: error.message
        });
    }
}));

app.put('/riders/:id/reject', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
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

app.patch('/riders/:id/status', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;
        const { status, email } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid rider ID'
            });
        }

        const validStatuses = ['active', 'inactive', 'deactivated'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status value. Allowed values: active, inactive, deactivated'
            });
        }

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

        if (status === 'active' && email) {
            const userResult = await userCollection.updateOne(
                { email: { $regex: `^${email.trim()}$`, $options: 'i' } },
                {
                    $set: { role: 'rider' }
                }
            );

            console.log('User role update result:', userResult);

            if (userResult.matchedCount === 0) {
                console.warn('No matching user found for email:', email);
            }
        }

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

    if (!parcelId || !trackingNumber || !amount || !userEmail || !transactionId) {
        return res.status(400).json({
            success: false,
            message: 'Missing required payment fields'
        });
    }

    const session = client.startSession();
    try {
        await session.withTransaction(async () => {
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

// Admin routes
app.get('/admin/users/search', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
    try {
        const { email, role } = req.query;
        const query = {};

        if (email) {
            query.email = { $regex: email, $options: 'i' };
        }
        if (role) {
            query.role = role;
        }

        const users = await userCollection.find(query)
            .project({ email: 1, role: 1, createdAt: 1, name: 1, _id: 1 })
            .sort({ createdAt: -1 })
            .limit(20)
            .toArray();

        res.json({
            success: true,
            data: users
        });
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to search users'
        });
    }
}));

app.put('/admin/users/:id/make-admin', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }

        const result = await userCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role: 'admin', updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User role updated to admin successfully'
        });
    } catch (error) {
        console.error('Error making user admin:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user role'
        });
    }
}));

app.put('/admin/users/:id/remove-admin', verifyFBToken, verifyAdmin, asyncHandler(async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }

        const result = await userCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role: 'user', updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'Admin privileges removed successfully'
        });
    } catch (error) {
        console.error('Error removing admin:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user role'
        });
    }
}));






// GET tracking info by tracking number
app.get('/parcels/tracking/:trackingNumber', async (req, res) => {
  try {
    const parcel = await parcelCollection.findOne({
      trackingNumber: req.params.trackingNumber
    });

    if (!parcel) {
      return res.status(404).json({
        success: false,
        message: "Parcel not found"
      });
    }

    // Return only necessary tracking data
    const trackingData = {
      trackingNumber: parcel.trackingNumber,
      status: parcel.status,
      deliveryStatus: parcel.deliveryStatus || [],
      senderRegion: parcel.senderRegion,
      receiverRegion: parcel.receiverRegion,
      assigned_rider: parcel.assigned_rider_name ? {
        name: parcel.assigned_rider_name,
        phone: parcel.assigned_rider_phone
      } : null,
      createdAt: parcel.createdAt
    };

    res.json({
      success: true,
      data: trackingData
    });

  } catch (error) {
    console.error("Tracking error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch tracking info"
    });
  }
});




// Add this to your routes
app.get('/admin/dashboard-stats', verifyFBToken, verifyAdmin, async (req, res) => {
  try {
    // Total parcels
    const totalParcels = await parcelCollection.countDocuments();
    
    // Parcel status counts
    const delivered = await parcelCollection.countDocuments({ status: 'delivered' });
    const inTransit = await parcelCollection.countDocuments({ status: 'in_transit' });
    const processing = await parcelCollection.countDocuments({ status: 'processing' });
    const cancelled = await parcelCollection.countDocuments({ status: 'cancelled' });
    
    // User stats
    const totalUsers = await userCollection.countDocuments();
    const newThisMonth = await userCollection.countDocuments({
      createdAt: { $gte: new Date(new Date().setDate(1)) }
    });
    
    // Monthly parcel stats (last 6 months)
    const monthlyStats = await parcelCollection.aggregate([
      {
        $group: {
          _id: { $month: "$createdAt" },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } },
      { $limit: 6 }
    ]).toArray();
    
    // User growth (last 6 months)
    const userGrowth = await userCollection.aggregate([
      {
        $group: {
          _id: { $month: "$createdAt" },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } },
      { $limit: 6 }
    ]).toArray();
    
    // Recent activity
    const recentActivity = await parcelCollection.aggregate([
      { $sort: { updatedAt: -1 } },
      { $limit: 5 },
      {
        $project: {
          message: {
            $concat: [
              "Parcel ", "$trackingNumber", 
              " status updated to ", "$status"
            ]
          },
          type: "delivery",
          timestamp: "$updatedAt"
        }
      }
    ]).toArray();
    
    res.json({
      parcels: {
        total: totalParcels,
        delivered,
        inTransit,
        processing,
        cancelled
      },
      users: {
        total: totalUsers,
        newThisMonth
      },
      monthlyStats: monthlyStats.map(month => ({
        month: new Date(2023, month._id - 1).toLocaleString('default', { month: 'short' }),
        count: month.count
      })),
      userGrowth: userGrowth.map(month => ({
        month: new Date(2023, month._id - 1).toLocaleString('default', { month: 'short' }),
        count: month.count
      })),
      recentActivity
    });
    
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});





// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Start the server
startServer();