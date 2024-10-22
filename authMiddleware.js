const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {

    try {
        // const token = req.headers['authorization'];
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).send('Access denied. No token provided.');
        }

        try {
            const decoded = jwt.verify(token,'your_jwt_secret');  
        
            req.user = decoded;
            next();
        } catch (err) {
console.log("testing",err);
            res.send(err);
        }
    } catch (error) {
        res.send(error);
    }



};

module.exports = authenticateToken;