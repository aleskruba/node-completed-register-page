const { Router } = require('express');
const authController = require('../controllers/authController');
const { requireAuth, checkUser,verifyUser} = require('../middleware/authMiddleware');

const router = Router();

router.get('/profile',requireAuth, async (req, res) => {
    res.render('profile')
 });
 

router.get('/signup', authController.signup_get);
router.post('/signup', authController.signup_post);
router.get('/login', authController.login_get);
router.post('/login', authController.login_post);
router.get('/logout', authController.logout_get);

router.get('/update',requireAuth,checkUser, authController.update_get);
router.put('/update', authController.update_put);

router.get('/changepassword',requireAuth,checkUser, authController.changepassword_get);
router.post('/changepassword',requireAuth,checkUser, authController.changepassword_post);

router.post('/fpassword', verifyUser,authController.fpassword_post);
router.get('/fpassword',authController.fpassword_get) 

router.post('/verifyOTP',authController.verifyOTP_post) 

router.get('/resetPassword',authController.resetPassword_get) 
router.post('/resetPassword',authController.resetPassword_post) 

module.exports = router;