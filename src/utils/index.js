const ipManipulation = require("./ipm");
module.exports = Object.assign({}, require("./config"), require("./keygen"), { ipManipulation });