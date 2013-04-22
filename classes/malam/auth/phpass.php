<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * @author  arie
 */

class Malam_Auth_Phpass extends Kohana_Auth_ORM
{
    /**
     * Phpass Hasher
     *
     * @var PasswordHash
     */
    protected $hasher;

    public function __construct($config = array())
    {
        parent::__construct($config);

        $this->hasher = new PasswordHash(10, FALSE);
    }


    /**
     * Logs a user in.
     *
     * @param   string   username
     * @param   string   password
     * @param   boolean  enable autologin
     * @return  boolean
     */
    protected function _login($user, $password, $remember)
    {
        $user = $this->_get_object($user);

        if ($user->loaded())
        {
            $password_matched = TRUE;
            $update_password  = TRUE;

            if (is_string($password))
            {
                if (strlen($user->password) == 64 && $this->hash($password) == $user->password)
                {
                    $update_password = TRUE;
                }
                else
                {
                    if ($this->_check_password($password, $user->password))
                    {
                        $update_password = FALSE;
                    }
                    else
                    {
                        $password_matched = FALSE;
                    }
                }
            }

            if ($password_matched)
            {
                if (TRUE === $update_password)
                {
                    $user->update_user(array(
                        'password_confirm'  => $password,
                        'password'          => $password
                    ));
                }

                if ($user->can_login())
                {
                    if ($remember === TRUE)
                    {
                        // Token data
                        $data = array(
                            'user_id'       => $user->pk(),
                            'expires'       => time() + $this->_config['lifetime'],
                            'user_agent'    => sha1(Request::$user_agent),
                        );

                        // Create a new autologin token
                        $token = ORM::factory('user_token')
                            ->values($data)
                            ->create();

                        // Set the autologin cookie
                        Cookie::set('authautologin', $token->token, $this->_config['lifetime']);
                    }

                    // Finish the login
                    $this->complete_login($user);

                    return TRUE;
                }
            }
        }

        // Login failed
        return FALSE;
    }

    public function phpass_hash($password)
    {
        return $this->hasher->HashPassword($this->_compile_password($password));
    }

    protected function _compile_password($password)
    {
        return $password . '::' . $this->hash($password);
    }

    /**
     * Compare password with original (hashed). Works for current (logged in) user
     *
     * @param   string  $password
     * @return  boolean
     */
    public function check_password($password)
    {
        $user = $this->get_user();

        if ( ! $user)
            return FALSE;

        return ( $this->_check_password($password, $user->password) );
    }

    protected function _check_password($password, $stored_hash)
    {
        return ($this->hasher->CheckPassword($this->_compile_password($password), $stored_hash));
    }

    protected function _get_object($user)
    {
        static $current;
        if ( ! is_object($current) AND is_string($user))
        {
            // Load the user
            $current = ORM::factory('user');
            $current->where($current->unique_key($user), '=', $user)->find();
        }

        return $current;
    }

    /**
     * try login with array data
     *
     * @param array $values
     * @return boolean
     */
    public function try_login(array $values)
    {
        $username = Arr::get($values, 'username');
        $password = Arr::get($values, 'password');
        $remember = Arr::get($values, 'remember');

        return $this->login($username, $password, $remember);
    }
}