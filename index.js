const server = require('./api/server.js');
require("dotenv").config();

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Listening on port ${PORT}...`);
});
