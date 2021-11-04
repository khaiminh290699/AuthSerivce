const amqplib = require("amqplib");
const { RABBITMQ_USER, RABBITMQ_PASS, RABBITMQ_HOST, RABBITMQ_PORT } = process.env;

let connect = null;

class RabbitMQ {
  constructor() {}

  init = async () =>{
    if (!this.connect) {
      this.connect = await amqplib.connect(`amqp://${RABBITMQ_USER}:${RABBITMQ_PASS}@${RABBITMQ_HOST}:${RABBITMQ_PORT}`);
    }
  }

  setup = async (option) => {
    const {
      exchange,
      queue,
      type = "direct",
      pattern = null
    } = option
    await this.init();
    const channel = await this.connect.createChannel();
    if (exchange) {
      await channel.assertExchange(exchange, type, { durable: true });
      await channel.assertQueue(queue, { durable: true });
      await channel.bindQueue(queue, exchange, pattern || queue);
    } else {
      await channel.assertQueue(queue, { durable: true });
    }
    return channel;
  }

  produce = async (data, option) => {
    const {
      exchange = "",
      queue
    } = option
    const channel = await this.setup(option);
    return await channel.publish(exchange, queue, Buffer.from(JSON.stringify(data)), { persistent: true });
  }

  consume = async (option, callback) => {
    const {
      queue,
      autoAck,
      exchange,
      pattern
    } = option
    const channel = await this.setup(option)
    await channel.consume(queue, async (message) => {
      const data = JSON.parse(message.content);
      try {
        callback(data, channel, message);
      } catch (err) {} finally {
        if (autoAck) {
          await channel.ack(message);
        }
      }
    })
  }

  rpc = async (data, option, callback) => {
    const {
      exchange,
      queue
    } = option

    await this.init();

    const channel = await connect.createChannel();
    const { queue: queueName } = await channel.assertQueue("", { exclusive: true, autoDelete: true });
    
    await channel.publish(exchange, queue, JSON.stringify(data), {
      replyTo: queueName
    });

    await channel.consume(queueName, async (message) => {
      const data = JSON.parse(message);
      try {
        await callback(data, channel, message);
      } catch (err) {}
    }, {
      noAck: true
    })
  }
}

module.exports = RabbitMQ;