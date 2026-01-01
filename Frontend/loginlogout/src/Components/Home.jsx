import { useNavigate } from 'react-router-dom'
export default function Home(){
    const navigate = useNavigate()
    return(
        <>
        <div className="w-full h-screen bg-green-500 flex items-center justify-center">
            <div className="text-center">
                <h1 className="text-4xl font-bold text-white mb-8">Welcome Home!</h1>
                <button 
                    onClick={() => navigate('/login')}
                    className="bg-white text-green-500 px-8 py-3 rounded-lg font-bold text-lg hover:bg-gray-100 transition"
                >
                    Go to Login/Logout
                </button>
            </div>
        </div>

        </>
    )
}
