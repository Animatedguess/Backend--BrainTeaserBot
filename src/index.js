import app from "./app.js";
import connectDB from "./db/index.js";



try {
    connectDB()
    .then(
        ()=>{
            let port;
            app.listen( port = process.env.PORT || 8000, () => {
                console.log(`server is connacted on ${port}`)
            })
        }
    )
    .catch((error)=>{
        console.log(error)
    })
} catch (error) {
    console.log(error);
}