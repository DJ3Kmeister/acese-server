const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const User = require('../models/User'); // Assurez-vous que ce chemin est correct
// Si vous avez un modèle Director séparé, décommentez la ligne suivante :
// const Director = require('../models/Director'); 

// @desc    Mot de passe oublié
// @route   POST /api/auth/forgot-password
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        // CORRECTION : On cherche l'utilisateur par son email SANS filtrer par rôle.
        // Ainsi, le Directeur (qui a le rôle "directeur" ou "admin") sera trouvé.
        let user = await User.findOne({ email });
        
        // Si vous avez une collection séparée pour les directeurs :
        // if (!user && Director) {
        //     user = await Director.findOne({ email });
        // }

        if (!user) {
            return res.status(404).json({ message: "Aucun compte trouvé avec cet email." });
        }

        // Génération du token
        const resetToken = crypto.randomBytes(20).toString('hex');

        // Hachage du token pour la sécurité
        user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

        await user.save();

        // URL de réinitialisation (à envoyer par email dans un vrai environnement)
        const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
        console.log(`Lien de réinitialisation : ${resetUrl}`); // À retirer en production

        res.status(200).json({ 
            success: true, 
            message: "Email de réinitialisation envoyé." 
        });

    } catch (error) {
        res.status(500).json({ message: "Erreur serveur", error: error.message });
    }
};

// @desc    Réinitialiser le mot de passe
// @route   POST /api/auth/reset-password/:token
exports.resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const resetPasswordToken = crypto.createHash('sha256').update(token).digest('hex');

        // Recherche de l'utilisateur (Directeur compris) avec le token valide
        let user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        // Si collection séparée :
        // if (!user && Director) {
        //     user = await Director.findOne({
        //         resetPasswordToken,
        //         resetPasswordExpire: { $gt: Date.now() }
        //     });
        // }

        if (!user) {
            return res.status(400).json({ message: "Token invalide ou expiré." });
        }

        // Hachage du nouveau mot de passe
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Effacement des champs de reset
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save();

        res.status(200).json({ 
            success: true, 
            message: "Mot de passe réinitialisé avec succès." 
        });

    } catch (error) {
        res.status(500).json({ message: "Erreur serveur", error: error.message });
    }
};
