const bcrypt = require('bcryptjs');

const plainPassword = 'admin123'; // your password
const hashedPassword = bcrypt.hashSync(plainPassword, 10);

console.log(hashedPassword);
