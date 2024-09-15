import {v2 as cloudinary} from "cloudinary";
import fs from "fs"
import { ApiError } from "./ApiError.js";


cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadOnCloudinary = async function(localFilePath){
    try {
        if(!localFilePath) return null
        //upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        // file has been uploaded successfully
        fs.unlinkSync(localFilePath)
        // console.log(response)
        return response;
    } catch (error) {
        fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the upload operation got failed
        return null;
        
    }
}

function extractPublicId(url) {
    // Remove the base URL part
    const parts = url.split('/');
    // Extract the public ID by removing the version and format parts
    const publicIdWithFormat = parts.slice(7).join('/'); // Skipping first six segments of the URL
    const publicId = publicIdWithFormat.split('.')[0]; // Remove the format (.jpg, .png, etc.)
    return publicId;
}

const deleteOnCloudinary = async function(localFilePath, fileType){
    try {
        if(!localFilePath) return null
        const response = await cloudinary.uploader.destroy(localFilePath, { resource_type: fileType || 'image' }, function(error, result) {
            if (error) {
              console.error('Error deleting image:', error);
            } else {
              console.log('Image deleted:', result);
            }
        })
        return response;
    } catch (error) {
        throw new ApiError(500, error?.message || "something went wrong at the time of deletion");
    }
}



export {
    uploadOnCloudinary,
    deleteOnCloudinary,
    extractPublicId
}