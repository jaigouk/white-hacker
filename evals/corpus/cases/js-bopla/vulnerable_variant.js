function update(user, body){
  Object.assign(user, body);  // SINK mass-assignment
  return user.save();
}
