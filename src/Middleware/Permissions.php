<?php namespace Mayconbordin\Entrust\Middleware;

use Mayconbordin\Entrust\Contracts\OwnershipResolverContract;
use Closure;
use \Auth;

class Permissions
{
    protected $user;
    protected $ownershipResolver;

    public function __construct(OwnershipResolverContract $ownershipResolver)
    {
        $this->user = Auth::user();
        $this->ownershipResolver = $ownershipResolver;
    }

	/**
	 * Handle an incoming request.
	 *
	 * @param  \Illuminate\Http\Request  $request
	 * @param  \Closure  $next
	 * @return mixed
	 */
	public function handle($request, Closure $next)
	{
		if ($this->isFreeToGo($request) || $this->hasPermission($request) || $this->hasRole($request)) {
            return $this->response($request, $next, true);
        }

		return $this->response($request, $next);
	}

    /**
     * Returns a response based on the authorized parameter.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure  $next
     * @param  bool $authorized
     * @return \Illuminate\Http\JsonResponse|\Illuminate\View\View
     */
	private function response($request, $next, $authorized = false)
	{
	    if (!$authorized) {
		    if ($request->ajax() || $request->wantsJson()) {
			    return response()->json(['errors' => ['Unauthorized.']], 401);
		    } else {
			    return view('errors.403');
		    }
        }
        
        return $next($request);
	}

    /**
     * Check if the user has any of the permissions necessary to access the resource. Note: the user only needs to have one of
     * the permissions, not all of them to be authorized.
     *
     * @param \Illuminate\Http\Request $request
     * @return bool
     */
    private function hasPermission($request)
    {
        $permissions = $this->getPermissions($request);
        $route = $request->route();

        foreach ($permissions as $permission) {
            if (strpos($permission, '-own-') !== false) {
                if ($this->user->can($permission) && $this->ownershipResolver->hasOwnership($permission, $this->user, $route)) {
                    return true;
                }
            } else if ($this->user->can($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the user has any of the roles necessary to access the resource. Note: the user only needs to have one of
     * the roles, not all of them to be authorized.
     *
     * @param \Illuminate\Http\Request $request
     * @return bool
     */
    private function hasRole($request)
    {
        $roles = $this->getRoles($request);

        foreach ($roles as $role) {
            if ($this->user->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if there are roles or permissions to be verified, if not then the user can proceed.
     *
     * @param \Illuminate\Http\Request $request
     * @return bool
     */
    private function isFreeToGo($request)
    {
        $roles       = $this->getRoles($request);
        $permissions = $this->getPermissions($request);

        if (sizeof($roles) == 0 && sizeof($permissions) == 0) {
            return true;
        }

        return false;
    }

    /**
     * Grab the permissions from the request
     *
     * @param \Illuminate\Http\Request $request
     * @return Array
     */
    private function getPermissions($request)
    {
        $actions = $request->route()->getAction();
 
        if (!isset($actions['permissions'])) {
            return [];
        } else {
            return is_array($actions['permissions']) ? $actions['permissions'] : [$actions['permissions']];
        }
    }
    
    /**
     * Grab the enabled roles from the request
     *
     * @param \Illuminate\Http\Request $request
     * @return Array
     */
    private function getRoles($request)
    {
        $actions = $request->route()->getAction();
        
        if (!isset($actions['roles'])) {
            return [];
        } else {
            return is_array($actions['roles']) ? $actions['roles'] : [$actions['roles']];
        }
    }
}
