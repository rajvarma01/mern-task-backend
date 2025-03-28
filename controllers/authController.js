import bcrypt from 'bcryptjs';
import User from '../models/user.js';

export const register = async (req, res) => {
    const { firstName, lastName, email, password, role } = req.body;
    try {
        const checkExistUser = await User.findOne({where: {email: email}});
        console.log('checkExistUser', checkExistUser)
        if (checkExistUser) {
             throw new Error('User already exists')
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ firstName, lastName, email, password: hashedPassword, role, isVerified: false });
        
        res.status(201).json({ message: 'User registered' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
        if (!user.isVerified) return res.status(400).json({ message: 'Email not verified' });
        if (user.role !== 'admin') return res.status(403).json({ message: 'You are not allowed to login from here' });
        
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: 'Invalid credentials' });

        res.json({ user });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};