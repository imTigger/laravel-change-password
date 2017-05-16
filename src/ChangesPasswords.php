<?php

namespace Imtigger\LaravelChangePassword;

use Auth;
use Hash;
use Session;
use Validator;

trait ChangesPasswords
{
    /**
     * Show the application's change password form.
     *
     * @return \Illuminate\Http\Response
     */
    public function showChangePasswordForm()
    {
        return view('auth.password', [
            'message' => Session::get('message')
        ]);
    }

    /**
     * Get the login username to be used by the controller.
     *
     * @return string
     */
    public function username()
    {
        return 'email';
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard();
    }

    protected function messageIncorrectCurrentPassword()
    {
        return trans('auth.incorrect_current_password');
    }

    protected function messagePasswordChanged()
    {
        return trans('auth.password_changed');
    }

    function changePassword(\Illuminate\Http\Request $request)
    {
        $validator = Validator::make($request->all(), [
            'password_current' => 'required',
            'password_new' => 'required|min:6|confirmed',
            'password_new_confirmation' => 'required'
        ]);

        $validator->after(function ($validator) use ($request) {
            if (!$this->guard()->validate([
                $this->username() => Auth::user()->getAttribute($this->username()),
                'password' => $request->get('password_current')
            ])
            ) {
                $validator->errors()->add('current_password', $this->messageIncorrectCurrentPassword());
            }
        });

        if ($validator->fails()) {
            return redirect()->back()->withInput()->withErrors($validator->errors());
        }

        $user = $this->guard()->user();
        $user->password = Hash::make($request->get('password_new'));
        $user->save();

        Session::flash('message', $this->messagePasswordChanged());

        return redirect()->back();
    }
}