const Users = require('../models/userModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const sgMail = require("@sendgrid/mail")


const {
    API_KEY,
    SENDER_EMAIL_ADDRESS,
    CLIENT_URL
} = process.env

sgMail.setApiKey(API_KEY)

const userCtrl = {
    register: async (req, res) => {
        try {
            const {name, email, password} = req.body

            if(!name || !email ||!password)
                return res.status(400).json({msg: "Please fill in all fields."})
            
            if(!validateEmail(email))
                return res.status(400).json({msg: "Invalid Email!"})
                // console.log(email)
            
            const user = await Users.findOne({email})
            if(user) return res.status(400).json({msg: "This email already exists."})

            if(password.length <6)
                return res.status(400).json({msg: "Password must be at least 6 characters."})
            
            const passwordHash =await bcrypt.hash(password, 12)
            // console.log({password, passwordHash})
            const newUser = {
                name, email, password: passwordHash
            }
            // console.log(newUser)

            const activation_token = createActivationToken(newUser)
            //console.log({activation_token})

            const url = `${CLIENT_URL}/user/activate/${activation_token}`
            // sendMail(email, url)
            
            const mailOptions = {
                from: SENDER_EMAIL_ADDRESS,
                to: (email),
                subject: "Account Activation",
                html: `
                    <div style="max-width: 700px; margin:auto; border: 10px solid #ddd; padding: 50px 20px; font-size: 110%;">
                    <h2 style="text-align: center; text-transform: uppercase;color: teal;">Welcome ${name} to Our Portal.</h2>
                    <p>Congratulations! You're almost set to start using Employee Management .
                        Just click the button below to validate your email address.
                    </p>
                    
                    <a href=${url} style="background: crimson; text-decoration: none; color: white; padding: 10px 20px; margin: 10px 0; display: inline-block;">Validate Here</a>
                
                    <p>If the button doesn't work for any reason, you can also click on the link below:</p>
                
                    <div>${url}</div>
                    </div>
                `
            }

            sgMail
                .send(mailOptions)
                .then((response) => console.log("E-mail sent successfully! "))
                .catch((error) => console.log(error.mailOptions));

            res.json({msg: "Registered Sucessfully! Please activate your account to start, Check your E-mail"})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    activateEmail: async (req, res) => {
        try {
            const {activation_token} = req.body
            const user = jwt.verify(activation_token, process.env.ACTIVATION_TOKEN_SECRET)

            // console.log(user)
            const {name, email, password} = user

            const check = await Users.findOne({email})
            if(check) return res.status(400).json({msg:"This email already exists."})

            const newUser = new Users({
                name, email, password
            })

            await newUser.save()
            res.json({msg:"Account has been activated!"})


        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    login: async (req, res) => {
        try {
            const {email, password} = req.body
            const user = await Users.findOne({email})
            if(!user) return res.status(400).json({msg: "This email does not exist."})

            const isMatch = await bcrypt.compare(password, user.password)
            if(!isMatch) return res.status(400).json({msg: "Password is incorrect."})

            console.log(user)
            
            const refresh_token = createRefreshToken({id: user._id})
            res.cookie('refreshtoken', refresh_token, {
                httpOnly: true,
                path: '/user/refresh_token',
                maxAge: 7*24*60*60*1000 //i.e. 7days
            })

            res.json({msg: "Login success!"})

        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    getAccessToken: (req, res) => {
        try {
            const rf_token = req.cookies.refreshtoken

            // console.log(rf_token)
            if(!rf_token) return res.status(400).json({msg: "Please login now"})

            jwt.verify(rf_token, process.env.REFRESH_TOKEN_SECRET, (err, user) =>{
                if (err) return res.status(400).json({msg: "Please login now"})
                // console.log(user)
                const access_token = createAcessToken({id: user.id})
                res.json({access_token})
            })

        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    forgotPassword: async (req, res) => {
        try {
            const {email} = req.body
            const user = await Users.findOne({email})
            if(!user) return res.status(400).json({msg: "This email does not exist."})

            const access_token = createAcessToken({id: user._id})
            const url = `${CLIENT_URL}/user/reset/${access_token}`

            const mailOptions = {
                from: SENDER_EMAIL_ADDRESS,
                to: (email),
                subject: "Password Reset",
                html: `
                    <div style="max-width: 700px; margin:auto; border: 10px solid #ddd; padding: 50px 20px; font-size: 110%;">
                    <h2 style="text-align: center; text-transform: uppercase;color: teal;">Welcome to Our Portal.</h2>
                    <p>OOps! You forgot the password, just one click away to use our service .
                        Just click the button below to validate your email address.
                    </p>
                    
                    <a href=${url} style="background: crimson; text-decoration: none; color: white; padding: 10px 20px; margin: 10px 0; display: inline-block;">Reset your Password</a>
                
                    <p>If the button doesn't work for any reason, you can also click on the link below:</p>
                
                    <div>${url}</div>
                    </div>
                `
            }

            sgMail
                .send(mailOptions)
                .then((response) => console.log("E-mail sent successfully for password reset! "))
                .catch((error) => console.log(error.mailOptions));

            res.json({msg: "Re-sent the password, please check your email."})

        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    resetPassword: async (req, res) => {
        try {
            const {password} = req.body
            console.log(password)
            const passwordHash = await bcrypt.hash(password, 12)

            await Users.findOneAndUpdate({_id: req.user.id}, {
                password: passwordHash
            })

            res.json({msg: "Password successfully changed!"})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    getUserInfor: async (req, res) => {
        try {
            const user = await Users.findById(req.user.id).select('-password')

            res.json(user)
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    getUsersAllInfor: async (req, res) => {
        try {
            const users = await Users.find().select('-password')

            res.json(users)
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    logout: async (req, res) => {
        try {
            res.clearCookie('refreshtoken', {path: '/user/refresh_token'})
            return res.json({msg: "You Logged out just now."})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    updateUser: async (req, res) => {
        try {
            const {name, avatar} = req.body
            await Users.findOneAndUpdate({_id: req.user.id}, {
                name, avatar
            })

            res.json({msg: "Update Success!"})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    updateUsersRole: async (req, res) => {
        try {
            const {role} = req.body

            await Users.findOneAndUpdate({_id: req.params.id}, {
                role
            })

            res.json({msg: "Update Success!"})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    deleteUser: async (req, res) => {
        try {
            await Users.findByIdAndDelete(req.params.id)

            res.json({msg: "Deleted Success!"})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },

        
}




function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
  }
    
const createActivationToken = (payload) => {
    return jwt.sign(payload, process.env.ACTIVATION_TOKEN_SECRET, {expiresIn: '5m'})
}

const createAcessToken = (payload) => {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15m'})
}

const createRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '7d'})
}



module.exports = userCtrl