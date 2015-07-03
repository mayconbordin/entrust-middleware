entrust-middleware
==================

A Laravel 5 middleware for Entrust.

## Installation

In order to install entrust-middleware, just add

```json
	"mayconbordin/entrust-middleware": "dev-master"
```
	
to your composer.json. Then run `composer install` or `composer update`.

Add the following line
	
```php
'permissions' => 'Mayconbordin\Entrust\Middleware\Permissions'
```

to your `app/Http/Kernel.php` file in the `$routeMiddleware` array.

## Ownership Resolver

To use the middleware you need to implement the `OwnershipResolverContract` and 
register the binding interface to your implementation.

The interface defines the method `hasOwnership($permission, $user, Route $route)`, 
which must return a boolean. The idea is that sometimes a permission is conditional,
meaning that the user can only access or do something to certain resource if he is
the owner of such resource.

Imagine, for example, a blog with multiple authors that can only edit their own posts.
For the permission to be evaluated by the `OwnershipResolverContract` service it must have
`-own-` in the name, in this case `edit-own-post`.

The implementation of the contract would look something like this:

```php
class OwnershipResolver implements OwnershipResolverContract
{
    public function hasOwnership($permission, $user, Route $route)
    {
        if ($permission == 'edit-own-post') {
            $post = Post::find($route->getParameter("id"));
            
            if ($post->author->id == $user->id) return true;
        }

        return false;
    }
}
```

You then register the implementation on the `register` method of `AppServiceProvider`:

```php
$this->app->bind(
    'Mayconbordin\Entrust\Middleware\Contracts\OwnershipResolverContract',
    'App\Services\OwnershipResolver'
);
```

## Usage

To check for a permission in a route:

```php
Route::put('/posts/{id}', [
    'uses'        => 'PostController@edit',
    'middleware'  => 'permissions',
    'permissions' => 'edit-own-post'
]);
```

Or you can check for a role instead:

```php
Route::put('/posts/{id}', [
    'uses'       => 'PostController@edit',
    'middleware' => 'permissions',
    'roles'      => 'admin'
]);
```

You can also check for both permissions and roles:

```php
Route::put('/posts/{id}', [
    'uses'        => 'PostController@edit',
    'middleware'  => 'permissions',
    'permissions' => 'edit-own-post',
    'roles'       => 'admin'
]);
```

In this case the user must have either the permission or the role. At last, you can
also list more than one permission or role:

```php
Route::put('/posts/{id}', [
    'uses'        => 'PostController@edit',
    'middleware'  => 'permissions',
    'permissions' => ['edit-post', 'edit-own-post']
]);
```
