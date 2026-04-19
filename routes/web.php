<?php

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;

Route::group([
    'prefix' => 'shopify-app-auth'
], function () {

    Route::get('install', [Config::get('shopify-oauth-laravel.controllers.install'), 'install'])
        ->name('shopify-install');

    Route::get('load', [Config::get('shopify-oauth-laravel.controllers.load'), 'load'])
        ->name('shopify-load');

    Route::post('uninstall', [Config::get('shopify-oauth-laravel.controllers.uninstall'), 'uninstall'])
        ->name('shopify-uninstall');

});