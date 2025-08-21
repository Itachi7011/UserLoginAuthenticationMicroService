const amqp = require('amqplib');
const EventEmitter = require('events');

class RabbitMQService extends EventEmitter {
  constructor() {
    super();
    this.connection = null;
    this.channel = null;
    this.isConnecting = false;
    this.connected = false;
  }

  async connect() {
    if (this.isConnecting || this.connected) return;
    this.isConnecting = true;

    console.log('Connecting to RabbitMQ...');
    
    try {
      this.connection = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672');
      this.channel = await this.connection.createChannel();
      
      // Create queues
      await this.channel.assertQueue('email_queue', { durable: true });
      await this.channel.assertQueue('audit_log_queue', { durable: true });
      await this.channel.assertQueue('api_metrics_queue', { durable: true });

      console.log('✅ Connected to RabbitMQ and queues created');
      this.connected = true;
      this.isConnecting = false;
      this.emit('connected');

      // Handle connection events
      this.connection.on('close', () => {
        console.log('RabbitMQ connection closed, reconnecting...');
        this.connected = false;
        this.channel = null;
        this.connection = null;
        setTimeout(() => this.connect(), 5000);
      });

      this.connection.on('error', (error) => {
        console.error('RabbitMQ connection error:', error.message);
        this.connected = false;
        this.channel = null;
        this.connection = null;
        setTimeout(() => this.connect(), 5000);
      });

    } catch (error) {
      console.error('Failed to connect to RabbitMQ:', error.message);
      this.connected = false;
      this.channel = null;
      this.connection = null;
      this.isConnecting = false;
      setTimeout(() => this.connect(), 5000);
    }
  }

  isReady() {
    return this.connected && this.channel !== null;
  }

  async sendToQueue(queue, message) {
    if (!this.isReady()) {
      console.error('RabbitMQ not ready. Message not sent:', message);
      return false;
    }

    try {
      const result = this.channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), {
        persistent: true
      });
      console.log(`✅ Message sent to ${queue} queue`);
      return result;
    } catch (error) {
      console.error('Error sending to queue:', error.message);
      return false;
    }
  }

  async consume(queue, callback) {
    if (!this.isReady()) {
      console.error('RabbitMQ not ready. Cannot setup consumer for:', queue);
      return false;
    }

    try {
      await this.channel.consume(queue, (message) => {
        if (message !== null) {
          const content = JSON.parse(message.content.toString());
          callback(content, () => this.channel.ack(message));
        }
      });
      console.log(`✅ Consumer setup for ${queue} queue`);
      return true;
    } catch (error) {
      console.error('Error setting up consumer:', error.message);
      return false;
    }
  }
}

// Create and export a singleton instance
const rabbitMQService = new RabbitMQService();
module.exports = rabbitMQService;