import { useState } from 'react'
import Login from './Components/Authentication/Login'
import { Routes, Route } from 'react-router-dom'
import Signup from './Components/Authentication/Signup'
import Home from './Components/Home'

function App() {

  return (
    <>
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Home />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/register" element={<Signup />} />
    </Routes>
    </>
  )
}

export default App

