const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");

function restrict() {
    const authError = {
        message: "Invalid Credentials"
    };
    return async (req, res, next) => {
        try {
            // const { username, password } = req.headers;
            // // make sure the values are not empty
            // if (!username || !password) {
            //     return res.status(401).json(authError);
            // }

            // const user = await Users.findBy({ username }).first();
            // // make sure the user exists in the database
            // if (!user) {
            //     return res.status(401).json(authError);
            // }

            // const passwordValid = await bcrypt.compare(password, user.password);
            // // make sure the password is correct
            // if (!passwordValid) {
            //     return res.status(401).json(authError);
            // }

            if (!req.session || !req.session.user) {
                return res.status(401).json(authError);
            }

            // if we reach this point, the user is considered authorized!
            next();
        } catch (err) {
            next(err);
        }
    };
}

module.exports = restrict;
