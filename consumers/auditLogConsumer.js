// consumers/auditLogConsumer.js
const amqp = require('amqplib');
const AuditLog = require('../models/AuditLog');

const startAuditLogConsumer = async () => {
    try {
        const connection = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://localhost');
        const channel = await connection.createChannel();

        await channel.assertQueue('audit_log_queue', { durable: true });
        console.log('Audit log consumer waiting for messages...');

        channel.prefetch(100); // Process up to 100 messages at a time

        channel.consume('audit_log_queue', async (msg) => {
            if (msg !== null) {
                try {
                    const logData = JSON.parse(msg.content.toString());
                    await AuditLog.create(logData);
                    console.log('Audit log saved:', logData.action);
                    channel.ack(msg);
                } catch (error) {
                    console.error('Error processing audit log message:', error);
                    channel.ack(msg); // Ack even on error to prevent queue blocking
                }
            }
        });
    } catch (error) {
        console.error('Audit log consumer error:', error);
        setTimeout(startAuditLogConsumer, 5000); // Retry after 5 seconds
    }
};

module.exports = startAuditLogConsumer;