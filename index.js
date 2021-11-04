const { Kafka, crypto } = require("./src/ultilities");
const { ModelUser } = require("./src/db");

const kafka = new Kafka();

kafka.consume("auth.user.list", { groupId: "auth.user.list" }, async (data, db) => {
  const { wheres = [], order = {}, pageSize, pageIndex } = data.params;

  const modelUser = new ModelUser(db);

  const users = await modelUser.queryByCondition(
    modelUser.query().select(modelUser.DB.raw(`users.*, COUNT(*) OVER()`)), 
    wheres, 
    pageIndex, 
    pageSize, 
    order
  );
  const total = users[0] ? +users[0].count : 0;
  return { status: 200, data: { users, total } }
})

kafka.consume("auth.signIn", { groupId: "auth.signIn" }, async (data, db) => {
  try {
    const { username, password } = data.params;

    if (!username || !password) {
      return { status: 400, message: "Missing params" }
    }
    const modelUser = new ModelUser(db);

    const user = await modelUser.insertOne({ username, password: await crypto.hash(password) });

    return { status: 200, data: { user } }
  } catch (err) {
    if (err.message.includes("users_username_unique")) {
      return { status: 400, message: "Username is exists" }
    }
    throw err
  }
});

kafka.consume("auth.updateInfo", { groupId: "auth.updateInfo" }, async (data, db) => {
  const { username, password, oldPassword, byAdmin } = data.params;

  const modelUser = new ModelUser(db);
  let user = await modelUser.findOne({ username });

  if (!user) {
    return { status: 404, message: "User not found" }
  }

  if (!byAdmin) {
    if (!await crypto.compare(oldPassword, user.password)) {
      return { status: 400, message: "Password is wrong" }
    }
  }

  user.username = username;
  user.password = await crypto.hash(password);
  
  user = await modelUser.updateOne(user);

  return { status: 200, data: { user } };
});

kafka.consume("auth.logIn", { groupId: "auth.logIn" }, async (data, db) => {
  const { username, password } = data.params;
  const modelUser = new ModelUser(db);

  const user = await modelUser.findOne({ username });
  if (!user) {
    return { status: 403, message: "Invlid username" }
  }
  
  if (!await crypto.compare(password, user.password)) {
    return { status: 403, message: "Invlid password" }
  }

  if (!user.is_activated) {
    return { status: 403, message: "User isn't activated" }
  }

  const token = crypto.sign({ id: user.id });

  delete user.password;
  user.token = token
  return { status: 200, data: { user } }
})

kafka.consume("auth.reset", { groupId: "auth.reset" }, async (data, db) => {
  const { user_id, password } = data.params;
  const modelUser = new ModelUser(db);

  let user = await modelUser.findOne({ id: user_id });
  if (!user) {
    return { status: 403, message: "Invlid username" }
  }
  
  user.password = await crypto.hash(password)
  user = await modelUser.updateOne(user);
  
  return { status: 200, data: { user } }
})

kafka.consume("auth.permission", { groupId: "auth.permission" }, async (data, db) => {
  const { user_id, permission } = data.params;
  const modelUser = new ModelUser(db);

  let user = await modelUser.findOne({ id: user_id });
  if (!user) {
    return { status: 403, message: "Invlid username" }
  }
  
  user.permission = permission
  user = await modelUser.updateOne(user);
  
  return { status: 200, data: { user } }
})

kafka.consume("auth.toggle", { groupId: "auth.toggle" }, async (data, db) => {
  const { user_id } = data.params;
  const modelUser = new ModelUser(db);

  let user = await modelUser.findOne({ id: user_id });
  if (!user) {
    return { status: 403, message: "Invlid username" }
  }
  
  user.is_activated = !user.is_activated;
  user = await modelUser.updateOne(user);
  
  return { status: 200, data: { user } }
})