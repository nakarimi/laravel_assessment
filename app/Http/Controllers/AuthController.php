<?php

namespace App\Http\Controllers;

use JWTAuth;

use Carbon\Carbon;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Validator;
use Junaidnasir\Larainvite\Facades\Invite;


class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['userProfile', 'login', 'register', 'signup', 'signupStore', 'confirmPin']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $jwt_token = null;

        if (!$jwt_token = JWTAuth::attempt($input)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Email or Password',
            ], Response::HTTP_UNAUTHORIZED);
        }

        return response()->json([
            'success' => true,
            'token' => $jwt_token,
        ]);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        DB::beginTransaction();
        try {

            $validator = Validator::make($request->all(), [
                'name' => 'required|string|between:2,100',
                'email' => 'required|string|email|max:100|unique:users',
                'password' => 'required|string|confirmed|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors()->toJson(), 400);
            }

            $user = User::create(array_merge(
                $validator->validated(),
                ['password' => bcrypt($request->password)]
            ));

            DB::commit();
            return response()->json([
                'message' => 'User successfully registered',
                'user' => $user
            ], 201);
        } catch (Exception $e) {
            DB::rollback();
            return Response::json($e, 400);
        }
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Store user profile data.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile(Request $request)
    {
        DB::beginTransaction();
        try {

            $validator = Validator::make($request->all(), [
                'user_name' => 'required|between:3,20',
                'avatar' => 'dimensions:width=256,height=256',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors()->toJson(), 400);
            }

            $files = $_FILES;
            $dir = 'avatars/';
            $stored = [];
            $file = file_get_contents($files['avatar']['tmp_name']);
            $extention =  pathinfo($files['avatar']['name'], PATHINFO_EXTENSION);
            $newName = time() . '.' . $extention;
            if (Storage::disk('local')->put($dir . $newName, $file)) {
                $stored = [
                    'path' => $dir . $newName,
                    'origname' => $files['avatar']['name'],
                    'newname' => $newName,
                    'mime' => $files['avatar']['type'],
                    'caption' => '',
                ];
            } else {
                $stored = $files['avatar']['error'];
            }

            $request->avatar = $stored['path'];

            $user = User::find($request->id);
            $user->update($request->all());

            DB::commit();
            return 'Information updated successfully';
        } catch (Exception $e) {
            DB::rollback();
            return Response::json($e, 400);
        }
    }
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

    public function invite(Request $request)
    {
        $user = Auth::user();
        $refCode = Invite::invite($request->email, $user->id);
        $email = 'nasseralikarimi@gmail.com';
        $subject = "Invitation Email";
        Mail::send([], [], function ($message) use ($email, $subject, $refCode) {
            $message->to($email)
                ->subject($subject)
                ->setBody('<h1>Hi, follow this link for registration!</h1>
              <a href="http://localhost:2000/api/signup/' . $refCode . '">Register</a>', 'text/html');
        });
        return 'Email sent Successfully';
    }
    public function confirmPin(Request $request, $pin)
    {
        DB::beginTransaction();
        try {

            $user = User::where('pin', $pin)->first();

            $user->update(
                [
                    'register_at' => Carbon::now(),
                    'pin' => null
                ]
            );
            DB::commit();
            return 'Email Confirmed Successflly. ID: ' . $user->id;
        } catch (Exception $e) {
            DB::rollback();
            return Response::json($e, 400);
        }
    }
    public function signupStore(Request $request, $code)
    {
        DB::beginTransaction();
        try {

            if (Invite::isAllowed($code, $request->email)) {
                // Register this user
                $validator = Validator::make($request->all(), [
                    'email' => 'required|string|email|max:100|unique:users',
                    'password' => 'required|string|min:6',
                ]);

                if ($validator->fails()) {
                    return response()->json($validator->errors()->toJson(), 400);
                }

                $user = User::create(array_merge(
                    $validator->validated(),
                    [
                        'password' => bcrypt($request->password),
                        'pin' => mt_rand(100000, 999999),
                    ]
                ));
                Invite::consume($code);
                DB::commit();
                return 'http://localhost:2000/api/confirm-pin/' . $user->pin;
            } else {
                return 'invalid or expired email';
            }
        } catch (Exception $e) {
            DB::rollback();
            return Response::json($e, 400);
        }
    }
}
