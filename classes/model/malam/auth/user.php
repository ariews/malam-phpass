<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * @author  arie
 */

class Model_Malam_Auth_User extends Model_Auth_User
{
    /**
     * Filters to run when data is set in this model. The password filter
     * automatically hashes the password when it's set in the model.
     *
     * @return array Filters
     */
    public function filters()
    {
        return array(
            'password' => array(
                array(array(Auth::instance(), 'phpass_hash'))
            )
        );
    }

    public function can_login()
    {
        $role = ORM::factory('role')->where('name', '=', 'login')->find();

        if ($role->loaded())
        {
            return $this->has('roles', $role);
        }

        return FALSE;
    }
}