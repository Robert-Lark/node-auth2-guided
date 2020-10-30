const jwt = require("jsonwebtoken");

const roles = ["basic", "admin"];

function restrict(role) {
	return async (req, res, next) => {
		try {
			//get the token from a cookie which is automatically sent from the client
			const token = req.cookies.token;
			if (!token) {
				return res.status(401).json({
					message: "Invalid credentials",
				});
			}

			//make sure the signature on the token is valid and still mathces the payload
			//we need to use the same secret string that was used to sign the token
			jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
				if (err) {
					return res.status(401).json({
						message: "Invalid credentials",
					});
				}

				// if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
				// 	return res.status(401).json({
				// 		message: "Invalid credentials",
				// 	});
				// }
				// make the token's decoded payload available to other mifflare functions or route handlers in case we want to use it later on
				req.token = decoded;
				console.log(decoded)
				if ((decoded.userRole === 'basic')) {
					return res.status(401).json({
						message: "You do not have clearence",
					});
				}

				//at this point we know the token and the user is authorized
				next();
			});
		} catch (err) {
			next(err);
		}
	};
}

module.exports = {
	restrict,
};
