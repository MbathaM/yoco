import 'dotenv/config';
import express from 'express';
import { createHmac, timingSafeEqual } from 'crypto';
import getRawBody from 'raw-body';
import morgan from 'morgan';
import cors from 'cors';
import serverless from "serverless-http";

const api = express();

// Set up Morgan logging middleware
api.use(morgan('dev'));

// Set up CORS middleware to allow requests from all origins
// app.use((req, res, next) => {
//     res.header('Access-Control-Allow-Origin', '*');
//     res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, webhook-id, webhook-timestamp, webhook-signature');
//     res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
//     if (req.method === 'OPTIONS') {
//         return res.sendStatus(200);
//     }
//     next();
// });

// Use CORS middleware
api.use(cors({
    origin: '*', // Or restrict to specific origins
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'webhook-id',
        'webhook-timestamp',
        'webhook-signature'
    ]
}));

api.use((req, res, next) => {
    getRawBody(req, {
        length: req.headers['content-length'],
        encoding: 'utf-8'
    }, (err, rawBody) => {
        if (err) return next(err);
        req.rawBody = rawBody;
        next();
    });
});

// Using Express
api.post("/my/webhook/url", function(req, res) {
    const headers = req.headers;
    const requestBody = req.rawBody;

    // Construct the signed content
    const id = headers['webhook-id'];
    const timestamp = headers['webhook-timestamp'];

    const signedContent = `${id}.${timestamp}.${requestBody}`;

    // Determine the expected signature
    const secret = process.env.YOCO_WEBHOOK_SECRET;
    const secretBytes = Buffer.from(secret.split('_')[1], "base64");
    // Replaced deprecated new Buffer() with Buffer.from()

    const expectedSignature = createHmac('sha256', secretBytes)
        .update(signedContent)
        .digest('base64');

    // Compare the signatures
    const signature = headers['webhook-signature'].split(' ')[0].split(',')[1]
    if (timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
        // process webhook event
        return res.send(200);
    }
    // do not process webhook event
    return res.send(403);
});

// Add a health route to test the API
api.get('/health', (req, res) => {
    res.json({ status: 'Ok' });
});

// Add a hello route to test the API
api.get('/', (req, res) => {
    res.json({ message: 'Hello from yoco' });
});

export const handler = serverless(api);

// Start the server
api.listen(3000, () => {
    console.log('Server is running on port 3000');
    console.log("Webhook secret:", process.env.YOCO_WEBHOOK_SECRET)
});
