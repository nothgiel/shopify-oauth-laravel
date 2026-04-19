<?php

namespace joymendonca\ShopifyOauthLaravel\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use App\Models\User;


class ShopifyUninstallController extends Controller
{
    public function uninstall(): void
    {
		$domain = request()->header('x-shopify-shop-domain');
		
        if($domain)
        {
            \Log::info("Shopify Store Uninstall initiated for ".$domain);

            $data = request()->getContent();
            $client_secret = Config::get('shopify-oauth-laravel.client_secret');
            $calculated_hmac = base64_encode(hash_hmac('sha256', $data, $client_secret, true));
            $received_hmac = (string) request()->header('x-shopify-hmac-sha256');
            // Constant-time comparison to avoid HMAC timing oracles.
            if (!hash_equals($calculated_hmac, $received_hmac))
                return;

			$store_has_users = Config::get('shopify-oauth-laravel.tables.store_has_users');
			
			$store = $this->getStoreModelClass()::query()->where('store_url', $domain)->first();
			$user = User::where('shopify_id', request()->input("id"))->first();
			
			if ($store and $user) {
				if (DB::table($store_has_users)
					->where('store_id', $store->id)
					->exists())
					DB::table($store_has_users)
					->where('store_id', $store->id)
					->delete();
				
				$store->delete();				
				
				if (!DB::table($store_has_users)
					->where('user_id', $user->id)
					->exists())
					$user->delete();
			}
			
			
            //$this->getStoreModelClass()::query()->where('store_url', request('myshopify_domain'))->delete();
            //$this->getUserModelClass()::query()->where('store_url', request('myshopify_domain'))->delete();
        }
    }


    protected function getUserModelClass(): string
    {
        return Config::get('auth.providers.users.model');
    }

    protected function getStoreModelClass(): string
    {
        return Config::get('shopify-oauth-laravel.models.store_model');
    }
}