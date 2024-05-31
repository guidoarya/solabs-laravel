<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $request->validate([
                'username' => 'required|unique:users',
                'password' => 'required|min:6',
                'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',
            ]);
        } catch (ValidationException $e) {
            return response()->json(['errors' => $e->errors()], 422); // Mengembalikan pesan kesalahan validasi
        }

        $imagePath = null;
    
        if ($request->hasFile('image')) {
            $image = $request->file('image');
            $imageName = time() . '_' . $image->getClientOriginalName();

            Log::info('Saving image with name: ' . $imageName);

            $imagePath = $image->storeAs('images', $imageName, 'uploads');
        }
    
        $user = User::create([
            'username' => $request->username,
            'password' => Hash::make($request->password),
            'image_url' => 'uploads/'. $imagePath,
        ]);
    
        return response()->json(['message' => 'User registered successfully'], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'username' => 'required',
            'password' => 'required',
        ]);

        $user = User::where('username', $request->username)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['token' => $token, 'user_data' => $user], 200);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out successfully'], 200);
    }
}
