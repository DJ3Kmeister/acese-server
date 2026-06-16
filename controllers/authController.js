const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Initialisation du client Supabase avec la clé de service (pour bypass RLS)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY; // Utilisez la clé "service_role" secret
const supabase = createClient(supabaseUrl, supabaseKey);

// @desc    Mot de passe oublié
// @route   POST /api/auth/forgot-password
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        // 1. Chercher dans la table 'users' sans filtrer par rôle
        let { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        // Si non trouvé dans 'users', on cherche dans 'directors' (si table séparée)
        if (!user) {
            let { data: director } = await supabase
                .from('directors')
                .select('*')
                .eq('email', email)
                .single();
            user = director;
        }

        if (!user) {
            return res.status(404).json({ message: "Aucun compte trouvé avec cet email." });
        }

        // 2. Générer le token
        const resetToken = crypto.randomBytes(20).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const expireDate = new Date(Date.now() + 10 * 60 * 1000).toISOString();

        // 3. Déterminer dans quelle table mettre à jour le token
        const tableName = user.role === 'directeur' ? 'directors' : 'users'; // Ajustez selon votre logique

        const { error: updateError } = await supabase
            .from(tableName)
            .update({ 
                reset_password_token: hashedToken, 
                reset_password_expire: expireDate 
            })
            .eq('id', user.id);

        if (updateError) throw updateError;

        // 4. Envoyer l'email (avec votre service)
        const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
        console.log(`Lien de réinitialisation : ${resetUrl}`);

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
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        // Chercher l'utilisateur avec ce token et non expiré
        let { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('reset_password_token', hashedToken)
            .gte('reset_password_expire', new Date().toISOString())
            .single();

        if (!user) {
            let { data: director } = await supabase
                .from('directors')
                .select('*')
                .eq('reset_password_token', hashedToken)
                .gte('reset_password_expire', new Date().toISOString())
                .single();
            user = director;
        }

        if (!user) {
            return res.status(400).json({ message: "Token invalide ou expiré." });
        }

        // Hacher le nouveau mot de passe
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Mettre à jour la BDD
        const tableName = user.role === 'directeur' ? 'directors' : 'users';
        await supabase
            .from(tableName)
            .update({ 
                password: hashedPassword,
                reset_password_token: null, 
                reset_password_expire: null 
            })
            .eq('id', user.id);

        res.status(200).json({ 
            success: true, 
            message: "Mot de passe réinitialisé avec succès." 
        });

    } catch (error) {
        res.status(500).json({ message: "Erreur serveur", error: error.message });
    }
};
