// Other imports
const path = require('path');

const fs = require('fs');
const multer = require('multer');
const cors = require('cors');
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
mongoose.connect('mongodb+srv://tutorial:tutorial%40123@tutorialcluster.wkkj3.mongodb.net/userdata', 

).then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log(err));

// Use SECRET_KEY from environment variables
const SECRET_KEY = 'yoursecretkey';

// User schema and model
const User = require('./models/User');
const Admin = require('./models/Admin');
const Course = require('./models/Course');
const Access = require('./models/Access');
//const VideoDelete = require('./models/VideoDelete'); // Adjust the path as necessary


function authenticateToken(req, res, next) {
  const token = req.body.token; // Expect token to be sent in body  
  if (!token) return res.sendStatus(401); // No token provided

  jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403); // Invalid token
      req.user = user; // Save user info for later use
      next();
  });
}
// Temporary OTP store
let otpStore = {};

// Email transport setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'siddusyed99@gmail.com', // Your email
    pass: 'fbtu byno pkvx dfyb'  // Your email password
  }
});

// Send OTP endpoint
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  
  
  // Generate a 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Store OTP with expiration (5 minutes)
  otpStore[email] = { otp, expiresIn: Date.now() + 300000 }; // 5 minutes
  
  // Send OTP via email
  const mailOptions = {
    from: '',
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}`
  };
  
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).send('Error sending OTP');
    } else {
      return res.send({success:'OTP sent successfully'});
    }
  });
});

// API: Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  console.log(email, otp);

  // Check if OTP exists for the user and is not expired
  const storedOtp = otpStore[email];
  console.log(storedOtp);

  if (storedOtp && storedOtp.otp === otp && storedOtp.expiresIn > Date.now()) {
    delete otpStore[email]; // OTP is valid, remove from store

    // If a new password is provided, update the user's password
    if (newPassword) {
      try {
        // Assuming you have a function to update the user's password in your database
        await updateUserPassword(email, newPassword);
        return res.send({ success: true, message: 'OTP verified and password updated successfully' });
      } catch (error) {
        console.error('Error updating password:', error);
        return res.status(500).send({ success: false, message: 'Error updating password' });
      }
    }

    return res.send({ success: true, message: 'OTP verified successfully' });
  } else {
    return res.status(400).send('Invalid or expired OTP');
  }
});


  async function updateUserPassword(email, newPassword) {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10); // Hash the new password
    await User.updateOne({ email }, { password: hashedPassword });
  }
// Sign-up endpoint
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

 

  try {
    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to database
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      isVerified: true,
    });

    await newUser.save();
    return res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract token from "Bearer <token>"

  if (!token) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Forbidden
    }
    req.user = user; // Attach user info to request
    next(); // Proceed to the next middleware or route handler
  });
};

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });

    const admin = await Admin.findOne({ email });
        
    if (admin) {
      if (admin.password!==password){
        return res.status(401).json({ success: false, message: 'Invalid password' });
      }
      const token = jwt.sign({ email: admin.email }, SECRET_KEY);
      

      return res.json({ success: true,email:admin.email,isadmin:admin.isAdmin, token });
    }
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    // Check if the password is valid
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log(isPasswordValid);
    if (!isPasswordValid) {
    
      return res.status(401).json({ success: false, message: 'Invalid password' });
    }

    // Check if the user is verified
    if (!user.isVerified) {
      return res.status(403).json({ success: false, message: 'User is not verified' });
    }

    // Generate a JWT token
    const token = jwt.sign({ email: user.email }, SECRET_KEY);

    res.json({ success: true, token, email });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});
app.post('/reset-password', async (req, res) => {
    const { otp, newPassword } = req.body;

    const user = await User.findOne({ otp });

    if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    // Hash new password and save it
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = ''; // Clear OTP after successful password reset
    await user.save();

    res.json({ success: true, message: 'Password reset successfully!' });
});
app.post('/check-email', async (req, res) => {
  const { email } = req.body;

  try {
      const user = await User.findOne({ email });
      if (user) {
          return res.status(200).json({ exists: true });
      }
      return res.status(404).json({ exists: false });
  } catch (err) {
      return res.status(500).json({ error: err.message });
  }
});
app.get('/courses', async (req, res) => {
  try {
      const courses = await Course.find(); // Fetch all courses
      res.json(courses); // Send the courses as JSON response
  } catch (error) {
      console.error('Error fetching courses:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});
app.get('/courses/:courseId', async (req, res) => {
  const { courseId } = req.params; // Extract courseId from request parameters
  try {
      const course = await Course.findOne({ id: courseId }); // Find course by id
      if (!course) {
          return res.status(404).json({ message: 'Course not found' });
      }
      res.json(course); // Send the course as JSON response
  } catch (error) {
      console.error('Error fetching course:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});
 const baseUploadDir = path.join(__dirname, 'uploads');

// // Create the base uploads directory if it doesn't exist
 if (!fs.existsSync(baseUploadDir)) {
    fs.mkdirSync(baseUploadDir);
 }

// // Set up multer storage configuration
const storage = multer.diskStorage({
   destination: (req, file, cb) => {
//         // Use the base upload directory directly
       cb(null, baseUploadDir);
  },
  filename: (req, file, cb) => {        cb(null,  file.originalname); // Generate a unique filename


}
  });

const upload = multer({ storage: storage });

// // Serve static files from the 'uploads' folder
 app.use('/uploads', express.static(baseUploadDir));
// Start the server
app.post('/upload', upload.single('file'), async (req, res) => {
  console.log("Uploaded Filename:", req.file.filename); // Debugging line
  const { title, description, category } = req.body;
console.log(category);
  try {
    // Find if the course with the provided category name already exists
    let course = await Access.findOne({ name: category });

    const url = "./uploads/"+req.file.filename; // Assign the uploaded file's filename to url
    let time=new Date()
    console.log(time);
    
    if (course) {
      // If the course exists, push the new video into the 'videos' array
      course.videos.push({ title, description, url,time });
    } else {
      // If the course does not exist, create a new one
      course = new Access({
        name: category, // Course name
        videos: [{ title, description, url ,time}] // Add the new video
      });
    }

    // Save the course (whether updated or newly created)
    await course.save();

    // Send success response
    res.status(200).json({ message: 'Video uploaded successfully!', course });
  } catch (error) {
    console.error('Error uploading video:', error);
    res.status(500).json({ message: 'Failed to upload video', error });
  }
});

app.post('/check-course-enrollment', async (req, res) =>  {
  const { jwt: token, category } = req.body;

  if (!token) {
    return res.status(401).json({ message: "Token is required." });
  }

  try {
    // Step 1: Decode the JWT to get the user information
    const decoded = jwt.verify(token, SECRET_KEY); // Use your actual secret key
    const email = decoded.email; // Assuming the email is stored in the token payload

    // Step 2: Check if the user exists in the database
    const user = await User.findOne({ email: email });
    

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Step 3: Check if the user is enrolled in any courses
    if (user.coursesEnrolled.length === 0) {
      return res.status(400).json({ message: "You must enroll in a course first." });
    }

    // Step 4: Check if the user is enrolled in the specified course
    const enrolledCourse = user.coursesEnrolled.find(course => 
      course.name && course.name.toLowerCase() === category.toLowerCase()
    );
   if (!enrolledCourse) {
      return res.status(400).json({ message: "You are not enrolled in this course." });
    }
    // Step 5: Fetch course data from Access collection
    const courseData = await Access.findOne({ name: category.toLowerCase()});

    if (!courseData) {
      return res.status(404).json({ message: "Course data not found. Admin cannot upload the videos." });
    }

    // Step 6: If the course exists, send the video details
    const videoDetails = courseData.videos.map(video => ({
      title: video.title,
      url: video.url,
      description: video.description
    }));

    res.json({
      message: "Enrollment confirmed.",
      courseName: courseData.name,
      videos: videoDetails
    });

  } catch (err) {
    console.error("Error processing request:", err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: "Invalid token." });
    }
    res.status(500).json({ message: "Error processing request." });
  }
});

app.post('/api/user/verify', async (req, res) => {
  const { email, jwt: token } = req.body; 
 console.log(email);
 
  
  
  // Check if the token is provided
  if (!token) {
      return res.status(403).json({ message: 'No token provided' });
  }

  // Verify the JWT
  try {
      const decoded = jwt.verify(token, SECRET_KEY);
      
      // Find the user by email
      const user = await User.findOne({ email: decoded.email }); // Assuming you have a User model

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }
      console.log(user);
      
      // Return user data (excluding sensitive information)
      res.json({
          name: user.name,
          email: user.email,
          isVerified: user.isVerified,
          coursesEnrolled: user.coursesEnrolled,
          certificates: user.certificates,
          completion:user.courseCompletion
      });
  } catch (err) {
      console.log('Verification Error:', err);
      return res.status(401).json({ message: 'Unauthorized! Invalid token.' });
  }
});
app.post('/api/courseDetails', authenticateToken, async (req, res) => {
  const { courseName } = req.body; // Get courseName from body
  console.log(courseName);
  
  // Check if the course exists
  const course =await Course.findOne({title: courseName});

  if (!course) {
      return res.status(404).json({ message: 'Course not found' });
  }

  // Assuming you have the user's email stored in the JWT payload
  const email = req.user.email; // Extract email from the token payload
  // Return course details
  res.json({
      courseName: course.title,
      price: course.price,
      email: email // Return email associated with the token
  });
});
app.post('/api/submitPayment', authenticateToken, async (req, res) => {
  const { firstName, lastName, courseName } = req.body;

  try {
      // Find user by email (as provided in the JWT)
      const user = await User.findOne({ email: req.user.email });

      if (!user) return res.status(404).send('User not found.');

      // Check if the course is already enrolled
      const courseExists = user.coursesEnrolled.some(course => course.name === courseName);

      if (!courseExists) {
          user.coursesEnrolled.push({ name: courseName }); // Add course if not already enrolled
      }

      // Check if the name needs updating
      const fullName = `${firstName} ${lastName}`;
       if (user.name !== fullName) {
        user.name = fullName; // Update name if it has changed
       }

      await user.save(); // Save updated user data

      res.status(200).json({
          message: 'Payment submitted successfully!',
          coursesEnrolled: user.coursesEnrolled,
          username: user.name, // Updated username
      });
  } catch (error) {
      console.error('Error during payment submission:', error);
      res.status(500).send('Server error');
  }
});
app.post('/update-progress', authenticateToken, async (req, res) => {
  const { token,videoId, courseName } = req.body; // Get video ID and course name from request body
  console.log(courseName);
  
  try {
      // Find the user by ID (assuming user ID is in the token)
      const user = await User.findOne({ email: req.user.email });
      if (!user) return res.status(404).json({ message: 'User not found.' });
      console.log(user);
      
      // Find the course in the enrolled courses
      const course = user.coursesEnrolled.find(course => course.name.toLowerCase() === courseName.toLowerCase());
      if (!course) return res.status(404).json({ message: 'Course not found.' });
      
      // Check if progress can be updated
      if (course.progress >= 100) {
          return res.status(400).json({ message: 'Progress already completed.' });
      }
      
      // Update progress by 10 points
      course.progress = Math.min(course.progress + 10, 100); // Ensure progress does not exceed 100
     
      // Check if progress is 75 or greater to add the course to certificates
      if (course.progress >= 75 && !user.certificates.some(cert => cert.courseName === courseName)) {
        user.certificates.push({
            courseName: courseName,
            date: formatDate() // Add formatted date
        });
    }

      await user.save(); // Save the updated user document

      res.json({ message: 'Progress updated successfully.', progress: course.progress });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error.' });
  }
});
function convertToIST(isoString) {
  const dateUTC = new Date(isoString);
const dateIST = new Date(dateUTC.getTime()  );
  
  const formattedDate = `${dateIST.getDate().toString().padStart(2, '0')}-${(dateIST.getMonth() + 1).toString().padStart(2, '0')}-${dateIST.getFullYear()} ${dateIST.getHours() % 12 || 12}:${dateIST.getMinutes().toString().padStart(2, '0')} ${dateIST.getHours() >= 12 ? 'PM' : 'AM'}`;
  
  return formattedDate;
}

// Route to get video uploads
app.get('/get-uploads', async (req, res) => {
  try {
      const accesses = await Access.find({});
      
      const uploads = accesses.flatMap(access => 
          access.videos.map(video => ({
              title: video.title,
              courseName: access.name,
              time: convertToIST(video.time), 
              status:"Published"// Convert time to IST
          }))
      );

      res.json(uploads);
  } catch (error) {
      console.error('Error fetching uploads:', error);
      res.status(500).send('Internal Server Error');
  }
});
app.get('/get-users-progress', async (req, res) => {
  try {
    const users = await User.find().select('name coursesEnrolled'); // Fetch only required fields

    // Map the data to the desired format
    const result = users.flatMap(user => 
      user.coursesEnrolled.map(course => ({
        userName: user.name,
        courseName: course.name,
        progress: course.progress,
      }))
    );

    res.json(result);
  } catch (error) {
    console.error('Error fetching user courses:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.delete('/delete-video/:category/:videoId', async (req, res) => {
  const { category, videoId } = req.params;

  // Validate if videoId is a valid ObjectId
  if (!mongoose.Types.ObjectId.isValid(videoId)) {
      return res.status(400).json({ message: 'Invalid video ID' });
  }

  try {
      // Find the course by category name
      const course = await Access.findOne({ name: category });
      
      if (!course) {
          return res.status(404).json({ message: 'Course not found' });
      }

      // Find and remove the video within the videos array
      const videoIndex = course.videos.findIndex(video => video._id.toString() === videoId);
      if (videoIndex === -1) {
          return res.status(404).json({ message: 'Video not found' });
      }

      course.videos.splice(videoIndex, 1);
      await course.save();

      res.status(200).json({ message: 'Video deleted successfully!' });
  } catch (error) {
      console.error('Error deleting video:', error);
      res.status(500).json({ message: 'Failed to delete video', error });
  }
});
app.get('/users/courses', async (req, res) => {
  try {
      // Fetch all users
      const users = await User.find();

      // Prepare the response array
      const userCourseDetails = await Promise.all(users.map(async (user) => {
          // Prepare an array for the courses of the current user
          const courseDetails = await Promise.all(user.coursesEnrolled.map(async (course) => {
              // Use a regex to find the corresponding course by name (case-insensitive)
              const courseData = await Course.findOne({ title: new RegExp(`^${course.name}$`, 'i') });
              return {
                  courseName: courseData ? courseData.title : course.name,
                  price: courseData ? courseData.price : null // Handle if course is not found
              };
          }));

          // Return user details with their course details
          return {
              username: user.name,
              courses: courseDetails
          };
      }));

      res.status(200).json(userCourseDetails);
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/certificates/counts', async (req, res) => {
  try {
    const users = await User.find();
    const certificateCounts = {};

    users.forEach(user => {
      user.certificates.forEach(certificate => {
        if (certificateCounts[certificate]) {
          certificateCounts[certificate]++;
        } else {
          certificateCounts[certificate] = 1;
        }
      });
    });

    res.status(200).json(certificateCounts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.get('/api/users', async (req, res) => {
  try {
    // Find all users
    const users = await User.find();

    // Map through users to extract relevant information
    const userData = users.map(user => ({
      username: user.name,
      email: user.email,
      courses: user.coursesEnrolled.map(course => ({
        courseName: course.name,
        isCompleted: user.courseCompletion.some(completion => completion.courseName === course.name),
      })),
    }));

    res.status(200).json(userData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.post('/delete-video', async (req, res) => {
  const { courseName, title } = req.body;
  console.log(courseName);
  
  // Validate input
  if (!courseName || !title) {
      return res.status(400).json({ message: "Course name and title are required" });
  }

  try {
      // Find the course and remove the video with the specified title
      const result = await Access.updateOne(
          { name: courseName },
          { $pull: { videos: { title: title } } }
      );

      // Check if any documents were modified
      if (result.modifiedCount === 0) {
          return res.status(404).json({ message: "Video not found or course does not exist" });
      }

      res.status(200).json({ message: "Video deleted successfully" });
  } catch (error) {
      console.error('Error deleting video:', error);
      res.status(500).json({ message: "An error occurred while deleting the video" });
  }
});
app.post('/api/certificate/details', async (req, res) => {
  const { courseName, token } = req.body; // Get courseName and token from the request body

  // Check if the token is provided
  if (!token) {
      return res.status(403).json({ message: 'No token provided' });
  }

  try {
      const decoded = jwt.verify(token, SECRET_KEY); // Verify the token
      
      // Find the user by email
      const user = await User.findOne({ email: decoded.email }); // Assuming you have a User model
        console.log(user);
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Check if the course name matches any of the user's enrolled courses
      if (!courseName) {
        return res.status(400).json({ message: 'Course name is required' });
    }
    
    const courseExists = user.coursesEnrolled.some(course => 
        course.name && course.name.toLowerCase() === courseName.toLowerCase()
    );
    console.log(courseExists);
    if (!courseExists) {
        return res.status(404).json({ message: 'Course not found for this user' });
    }
      // Find the certificate details
      const certificate = user.certificates.find(cert => cert.courseName === courseName);
      console.log(certificate);
      if (!certificate) {
          return res.status(404).json({ message: 'Certificate not found' });
      }

      // Return the certificate details
      res.json({
          userName: user.name,
          courseName: certificate.courseName,
          date: certificate.date
      });
  } catch (error) {
      if (error.name === 'JsonWebTokenError') {
          console.error('Invalid token:', error);
          return res.status(401).json({ message: 'Invalid token' }); // Unauthorized
      }
      console.error('Error fetching certificate details:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});
function formatDate() {
  const options = { year: 'numeric', month: 'long', day: 'numeric' };
  return new Date().toLocaleDateString(undefined, options);
}
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
