const jwt = require('jsonwebtoken');

module.exports = (allowedRoles) => (req, res, next) => {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }

    try {
        // Extract the token from the Bearer authorization header
        const decoded = jwt.verify(token.split(' ')[1], 'secretKey');

        // Check if the decoded role is included in the allowedRoles
        if (!allowedRoles.includes(decoded.role)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        req.user = decoded; // Attach user info (id, role) to the request
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};
