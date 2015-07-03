<?php namespace Mayconbordin\Entrust\Contracts;

use Illuminate\Routing\Route;

interface OwnershipResolverContract {
    /**
     * Verify if the user has the given permission for the resource.
     *
     * @param  string $permission
     * @param  User   $user
     * @param  Route  $route
     * @return bool
     */
    public function hasOwnership($permission, $user, Route $route);
}
