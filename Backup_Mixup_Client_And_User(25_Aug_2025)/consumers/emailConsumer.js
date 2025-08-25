// consumers/emailConsumer.js
const amqp = require('amqplib');
const { sendOTPEmail, sendWelcomeEmail } = require('../utils/emailService');

const startEmailConsumer = async () => {
    try {
        const connection = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://localhost');
        const channel = await connection.createChannel();

        await channel.assertQueue('email_queue', { durable: true });
        console.log('Email consumer waiting for messages...');

        channel.prefetch(1); // Process one message at a time

        channel.consume('email_queue', async (msg) => {
            if (msg !== null) {
                try {
                    const emailData = JSON.parse(msg.content.toString());
                    console.log('Processing email:', emailData);

                    let success = false;

                    if (emailData.template === 'otp') {
                        success = await sendOTPEmail(emailData.to, emailData.context);
                    } else if (emailData.template === 'welcome') {
                        success = await sendWelcomeEmail(emailData.to, emailData.context);
                    }

                    if (success) {
                        console.log('Email sent successfully');
                        channel.ack(msg);
                    } else {
                        console.log('Failed to send email, requeuing');
                        channel.nack(msg, false, true); // Requeue the message
                    }
                } catch (error) {
                    console.error('Error processing email message:', error);
                    channel.nack(msg, false, false); // Discard the message
                }
            }
        });
    } catch (error) {
        console.error('Email consumer error:', error);
        setTimeout(startEmailConsumer, 5000); // Retry after 5 seconds
    }
};

module.exports = startEmailConsumer;