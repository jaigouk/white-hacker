function update(user, body){
  user.name = body.name; user.email = body.email;
  return user.save();
}
