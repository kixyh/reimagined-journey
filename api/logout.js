module.exports = (req, res) => {
  res.setHeader('Set-Cookie', 'sess=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax');
  res.redirect('/');
};
