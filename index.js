require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'Tilux';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkeyfortiluxauth12345';

// Middlewares
app.use(cors({
    origin: '*', // For development flexibility
    credentials: true
}));
app.use(express.json());

let db;
let client;

// Connect to MongoDB
async function connectDB() {
    try {
        client = new MongoClient(MONGO_URI);
        await client.connect();
        db = client.db(DB_NAME);
        console.log(`Connected to MongoDB database: ${DB_NAME}`);
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}

connectDB();

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ message: 'No authorization token provided' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

// Middleware to check if user is a Shop Owner
const verifyShopOwner = (req, res, next) => {
    if (req.user.role !== 'shop_owner') {
        return res.status(403).json({ message: 'Access denied. Shop Owner role required.' });
    }
    next();
};

// ==================== AUTH ENDPOINTS ====================

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password, role, image } = req.body;
        
        if (!name || !email || !password || !role) {
            return res.status(400).json({ message: 'Name, email, password, and role are required' });
        }
        
        const usersCol = db.collection('Users');
        
        // Check if user already exists
        const existingUser = await usersCol.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }
        
        // Validate role
        if (role !== 'shop_owner' && role !== 'buyer') {
            return res.status(400).json({ message: 'Invalid role. Must be shop_owner or buyer.' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = {
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            role,
            image: image || '',
            createdAt: new Date()
        };
        
        const result = await usersCol.insertOne(newUser);
        res.status(201).json({ 
            message: 'User created successfully', 
            userId: result.insertedId 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during signup' });
    }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        
        const usersCol = db.collection('Users');
        const user = await usersCol.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        
        // Sign JWT
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                image: user.image
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// GET PROFILE
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const usersCol = db.collection('Users');
        const user = await usersCol.findOne({ _id: new ObjectId(req.user.id) });
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json({
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            image: user.image
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching profile' });
    }
});

// UPDATE PROFILE
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const { name, image } = req.body;
        const updateDoc = {};
        
        if (name) updateDoc.name = name;
        if (image !== undefined) updateDoc.image = image;
        
        if (Object.keys(updateDoc).length === 0) {
            return res.status(400).json({ message: 'Nothing to update' });
        }
        
        const usersCol = db.collection('Users');
        await usersCol.updateOne(
            { _id: new ObjectId(req.user.id) },
            { $set: updateDoc }
        );
        
        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating profile' });
    }
});


// ==================== TILES CRUD ENDPOINTS ====================

// GET ALL TILES
app.get('/api/tiles', async (req, res) => {
    try {
        const tilesCol = db.collection('Tiles');
        const tiles = await tilesCol.find({}).toArray();
        
        // Map _id to id for client compatibility
        const formattedTiles = tiles.map(t => ({
            id: t._id.toString(),
            ...t,
            _id: undefined
        }));
        
        res.json(formattedTiles);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching tiles' });
    }
});

// GET SINGLE TILE
app.get('/api/tiles/:id', async (req, res) => {
    try {
        const tilesCol = db.collection('Tiles');
        let query;
        
        if (ObjectId.isValid(req.params.id)) {
            query = { _id: new ObjectId(req.params.id) };
        } else {
            // Keep support for string IDs if any (like tile_001)
            query = { _id: req.params.id };
        }
        
        const tile = await tilesCol.findOne(query);
        
        if (!tile) {
            // Fallback: search by custom string id if we have seeded them with custom ID fields
            const fallbackTile = await tilesCol.findOne({ id: req.params.id });
            if (!fallbackTile) {
                return res.status(404).json({ message: 'Tile not found' });
            }
            return res.json(fallbackTile);
        }
        
        res.json({
            id: tile._id.toString(),
            ...tile,
            _id: undefined
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching tile' });
    }
});

// CREATE TILE (Shop Owner only)
app.post('/api/tiles', authenticateToken, verifyShopOwner, async (req, res) => {
    try {
        const { title, description, image, category, price, dimensions, material, inStock } = req.body;
        
        if (!title || !image || price === undefined) {
            return res.status(400).json({ message: 'Title, image, and price are required' });
        }
        
        const newTile = {
            title,
            description: description || '',
            image,
            category: category || '',
            price: Number(price),
            currency: 'USD',
            dimensions: dimensions || '',
            material: material || '',
            inStock: inStock !== undefined ? Boolean(inStock) : true,
            createdBy: req.user.id,
            createdAt: new Date()
        };
        
        const tilesCol = db.collection('Tiles');
        const result = await tilesCol.insertOne(newTile);
        
        res.status(201).json({
            message: 'Tile created successfully',
            id: result.insertedId.toString()
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error creating tile' });
    }
});

// UPDATE TILE (Shop Owner only)
app.put('/api/tiles/:id', authenticateToken, verifyShopOwner, async (req, res) => {
    try {
        const { title, description, image, category, price, dimensions, material, inStock } = req.body;
        const updateDoc = {};
        
        if (title) updateDoc.title = title;
        if (description !== undefined) updateDoc.description = description;
        if (image) updateDoc.image = image;
        if (category !== undefined) updateDoc.category = category;
        if (price !== undefined) updateDoc.price = Number(price);
        if (dimensions !== undefined) updateDoc.dimensions = dimensions;
        if (material !== undefined) updateDoc.material = material;
        if (inStock !== undefined) updateDoc.inStock = Boolean(inStock);
        
        if (Object.keys(updateDoc).length === 0) {
            return res.status(400).json({ message: 'Nothing to update' });
        }
        
        const tilesCol = db.collection('Tiles');
        let query;
        if (ObjectId.isValid(req.params.id)) {
            query = { _id: new ObjectId(req.params.id) };
        } else {
            query = { id: req.params.id };
        }
        
        const result = await tilesCol.updateOne(query, { $set: updateDoc });
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'Tile not found' });
        }
        
        res.json({ message: 'Tile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating tile' });
    }
});

// DELETE TILE (Shop Owner only)
app.delete('/api/tiles/:id', authenticateToken, verifyShopOwner, async (req, res) => {
    try {
        const tilesCol = db.collection('Tiles');
        let query;
        if (ObjectId.isValid(req.params.id)) {
            query = { _id: new ObjectId(req.params.id) };
        } else {
            query = { id: req.params.id };
        }
        
        const result = await tilesCol.deleteOne(query);
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'Tile not found' });
        }
        
        res.json({ message: 'Tile deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error deleting tile' });
    }
});

// ==================== ORDERS ENDPOINTS ====================

// PLACE AN ORDER
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { tileId, quantity } = req.body;
        if (!tileId) {
            return res.status(400).json({ message: 'Tile ID is required' });
        }
        const tilesCol = db.collection('Tiles');
        let tileQuery = ObjectId.isValid(tileId) ? { _id: new ObjectId(tileId) } : { id: tileId };
        const tile = await tilesCol.findOne(tileQuery);
        if (!tile) {
            return res.status(404).json({ message: 'Tile not found' });
        }

        const newOrder = {
            buyerId: req.user.id,
            buyerEmail: req.user.email,
            tileId: tileId,
            tileTitle: tile.title,
            tileImage: tile.image,
            tilePrice: tile.price,
            quantity: Number(quantity) || 1,
            totalPrice: tile.price * (Number(quantity) || 1),
            status: 'Pending',
            createdAt: new Date()
        };

        const ordersCol = db.collection('Orders');
        const result = await ordersCol.insertOne(newOrder);
        res.status(201).json({
            message: 'Order placed successfully',
            orderId: result.insertedId.toString()
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error placing order' });
    }
});

// GET ORDERS (Buyer: only self, Shop Owner: all)
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const ordersCol = db.collection('Orders');
        let query = {};
        if (req.user.role !== 'shop_owner') {
            query = { buyerId: req.user.id };
        }
        const orders = await ordersCol.find(query).sort({ createdAt: -1 }).toArray();
        
        const formattedOrders = orders.map(o => ({
            id: o._id.toString(),
            ...o,
            _id: undefined
        }));
        res.json(formattedOrders);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error fetching orders' });
    }
});

// UPDATE ORDER STATUS (Shop Owner only)
app.patch('/api/orders/:id', authenticateToken, verifyShopOwner, async (req, res) => {
    try {
        const { status } = req.body;
        if (!status) {
            return res.status(400).json({ message: 'Status is required' });
        }
        
        const ordersCol = db.collection('Orders');
        const query = ObjectId.isValid(req.params.id) ? { _id: new ObjectId(req.params.id) } : { id: req.params.id };
        
        const result = await ordersCol.updateOne(query, { $set: { status } });
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json({ message: 'Order status updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error updating order' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
