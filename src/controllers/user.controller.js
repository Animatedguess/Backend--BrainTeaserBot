import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User} from "../models/user.model.js"
import {deleteOnCloudinary, extractPublicId, uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";


const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHandler( async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: firstName, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res


    const {firstName, lastName, email, password } = req.body
    //console.log("email: ", email);

    if (
        [firstName, email, lastName, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        email 
    })

    if (existedUser) {
        throw new ApiError(409, "User with email already exists")
    }
    //console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;
    

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    let avatar;
try {
    avatar = await uploadOnCloudinary(avatarLocalPath);
} catch (error) {
    throw new ApiError(500, "Failed to upload avatar to Cloudinary");
}


    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }
   

    const user = await User.create({
        firstName,
        avatar: avatar.url,
        email, 
        password,
        lastName,
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )

} )

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Check if email is provided
    if (!email) {
        throw new ApiError(400, "Email is required");
    }

    // Find the user by email
    const user = await User.findOne({ email });

    // Check if user exists
    if (!user) {
        throw new ApiError(404, "User does not exist");
    }

    // Verify the password
    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials");
    }

    // Generate access and refresh tokens
    const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id);

    // Get user details excluding password and refreshToken fields
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    // Set cookie options
    const options = {
        httpOnly: true,      // Prevents access to the cookie via JavaScript
        secure: process.env.NODE_ENV === 'production', // Use secure cookie in production
        sameSite: 'Strict',  // Helps prevent CSRF attacks
    };

    // Send cookies and response
    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, {
                user: loggedInUser,
                accessToken,
                refreshToken,
            }, "User logged in successfully")
        );
});


const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
            
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200, 
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    // Fetch the user by ID
    const user = await User.findById(req.user?._id);

    // Check if the old password is correct
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    // If the old password is incorrect, throw an error
    if (!isPasswordCorrect) {
        throw new ApiError(400, 'Invalid old password');
    }

    // Set the new password (it will be hashed before saving)
    user.password = newPassword;
    
    // Save the user, skipping password validation
    await user.save({ validateBeforeSave: false });

    // Respond with success message
    return res
        .status(200)
        .json(new ApiResponse(200, {}, 'Password changed successfully'));
});


const getCurrentUser = asyncHandler(async (req, res) => {
    if (!req.user) {
      return res.status(401).json(new ApiResponse(401, null, "Unauthorized"));
    }
    return res.status(200).json(new ApiResponse(200, req.user, "User fetched successfully"));
});  

const updateAccountDetails = asyncHandler(async(req, res) => {
    const {firstName, lastName, email} = req.body

    if (!firstName || !lastName || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                firstName,
                lastName,
                email: email,
            }
        },
        {new: true}
        
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
});

const updateUserAvatar = asyncHandler(async(req, res) => {
    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    //TODO: delete old image - assignment
    
    await deleteOnCloudinary(extractPublicId(req.user.avatar))

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")
        
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar image updated successfully")
    )
})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
}