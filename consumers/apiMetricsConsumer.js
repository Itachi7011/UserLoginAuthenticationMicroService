// consumers/apiMetricsConsumer.js
const amqp = require('amqplib');
const Client = require('../models/Client');
const User = require('../models/User');

const startApiMetricsConsumer = async () => {
    try {
        const connection = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://localhost');
        const channel = await connection.createChannel();

        await channel.assertQueue('api_metrics_queue', { durable: true });
        console.log('API metrics consumer waiting for messages...');

        channel.prefetch(100); // Process up to 100 messages at a time

        channel.consume('api_metrics_queue', async (msg) => {
            if (msg !== null) {
                try {
                    const metricsData = JSON.parse(msg.content.toString());

                    // Update client request count
                    await Client.updateOne(
                        { _id: metricsData.clientId },
                        { $inc: { 'subscription.currentRequests': 1 } }
                    );

                    // Update user request count if userId is provided
                    if (metricsData.userId) {
                        await User.updateOne(
                            { _id: metricsData.userId },
                            { $inc: { 'subscription.currentRequests': 1 } }
                        );
                    }

                    console.log('API metrics updated for client:', metricsData.clientId);
                    channel.ack(msg);
                } catch (error) {
                    console.error('Error processing API metrics message:', error);
                    channel.ack(msg); // Ack even on error to prevent queue blocking
                }
            }
        });
    } catch (error) {
        console.error('API metrics consumer error:', error);
        setTimeout(startApiMetricsConsumer, 5000); // Retry after 5 seconds
    }
};

module.exports = startApiMetricsConsumer;