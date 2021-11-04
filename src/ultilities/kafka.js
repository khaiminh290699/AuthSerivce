
const kafka = require('kafkajs');
const { DB } = require('../db');
const { KAFKA_HOST, KAFKA_CLIENT } = process.env

class Kafka {

  constructor() {
    this.client = new kafka.Kafka({
      clientId: KAFKA_CLIENT,
      brokers: [KAFKA_HOST],
      connectionTimeout: 10000
    })
  };

  produce = async (topic, key, value) => {
    const producer = this.client.producer({ retry: 1 });
    await producer.connect();
    await producer.send({
      topic,
      messages: [{ key, value: JSON.stringify(value) }]
    });
    await producer.disconnect();
  }

  consume = async (topic, options, callback) => {
    const { groupId, fromBeginning = false } = options;
    const consumer = this.client.consumer({
      groupId,
      retry: 1
    });
    await consumer.subscribe({ topic, fromBeginning });
    await consumer.run({
      eachMessage: async ({ message }) => {
        const data = JSON.parse(message.value.toString());
        const db = new DB();
        try {
          const result = await callback(data, db);
          if (data.responseId) {
            await this.produce(data.responseId, null, result);
          }
        } catch (err) {
          console.log(err);
          if (data.responseId) {
            await this.produce(data.responseId, null, { status: 500, message: `SystemError: ${err.message}`, data: { responseId: data.responseId } });
          }
        } finally {
          await db.DB.destroy();
        }
      },
    })
  }

  rpc = async (topic, key, value) => {
    return new Promise(async (resolve, reject) => {
      const responseId = uuid.v4();

      let admin = this.client.admin();
      await admin.connect();
      await admin.createTopics({
        topics: [
          {
            topic: responseId,
            numPartitions: 1
          },
        ]
      })

      const consumer = this.client.consumer({
        groupId: responseId
      });
      await consumer.subscribe({ topic: responseId, fromBeginning: true });
      await consumer.run({
        eachMessage: async ({ message }) => {
          await admin.deleteTopics({ topics: [ responseId ] });
          await admin.disconnect();
          admin = null;
          return resolve(JSON.parse(message.value.toString()));
        },
      })
  
      const producer = this.client.producer({ retry: 1 });
      await producer.connect();
      await producer.send({
        topic,
        messages: [{ key, value: JSON.stringify({ ...value, responseId }) }]
      });
      await producer.disconnect();

      setTimeout(async () => {
        if (admin) {
          await admin.deleteTopics({ topics: [ responseId ] });
          await admin.disconnect();
          return reject(new Error(`TimeoutError: Event ${topic} time-out`));
        }
      }, 30000);
    })

  }
}

module.exports = Kafka;