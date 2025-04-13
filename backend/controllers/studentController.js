import asyncHandler from 'express-async-handler';
import Student from '../models/studentModel.js'
import bcrypt from 'bcryptjs'
import generateToken from '../utils/generateToken.js'

//@desc Auth student & get token
//@route POST  /api/student/login
//@access Public
const authUser = asyncHandler(async(req, res) => {
	const { stud_email, password } = req.body
	const user = await Student.findOne({ stud_email })

	if(user) {
		const verified = bcrypt.compareSync(password, user.password);
		if(verified) {
			res.status(201).json({
				_id: user._id,
				stud_name: user.stud_name,
				stud_email: user.stud_email,
				user_type: "student",
				stud_mobile: user.stud_mobile,
				stud_address: user.stud_address,
				stud_pic: user.stud_pic,
				course: user.course,
				exam: user.exam,
				token: generateToken(user._id)
			})
		}
		else {
			res.status(400)
			throw new Error('Incorrect password')
		}
	}
	else {
		res.status(404)
		throw new Error('User not found')
	}
})

//@desc Register a new student
//@route POST  /api/student/register
//@access Public
const registerUser = asyncHandler(async(req, res) => {
	const { 
		stud_name, 
		stud_email,
		password,
		stud_mobile,
		stud_address,
		stud_pic
	} = req.body

	const userExists = await Student.findOne({ stud_email })

	if(userExists) {
		res.status(400)
		throw new Error('Student already exists')
	}

	const salt = bcrypt.genSaltSync(10);
	const hashedPassword = bcrypt.hashSync(password, salt);

	const user = await Student.create({
		stud_name,
		stud_email,
		password: hashedPassword,
		stud_mobile,
		stud_address,
		stud_pic,
		course: [],
		exam: []
	})

	if(user) {
		res.status(201).json({
			_id: user._id,
			stud_name: user.stud_name,
			stud_email: user.stud_email,
			user_type: "student",
			stud_mobile: user.stud_mobile,
			stud_address: user.stud_address,
			stud_pic: user.stud_pic,
			course: user.course,
			exam: user.exam,
			token: generateToken(user._id)
		})
	}
	else {
		res.status(400)
		throw new Error('Invalid user data')
	}
})

export { authUser, registerUser }