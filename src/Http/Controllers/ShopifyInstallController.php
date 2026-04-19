<?php

namespace joymendonca\ShopifyOauthLaravel\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Config;
use App\Models\Visit;
use App\Models\Client;

class ShopifyInstallController extends Controller
{
    public function install(): RedirectResponse
    {
        $cookieValue = request()->cookie('shopify_install_context');
        $domain = null;

        if ($cookieValue) {
            $context = decrypt($cookieValue);
            $domain = $context['return_domain'];
        }

        if (!$cookieValue or !$domain) {
            // Fallback: no cookie found
            $visit = Visit::where("ip", request()->ip())
                ->latest()
                ->first();
            
            if ($visit) {
                $client = Client::where("refer", $visit->refer_id)->first();

                if ($client and $client->custom_domain)
                    $domain = $client->primary_domain;
                else
                    $domain = "dropstart.app";
            } else
                $domain = "dropstart.app";
        }		
		
        if(request('host') && request('shop'))
        {
            // Security: only allow *.myshopify.com shops as redirect targets,
            // otherwise the `shop` param can redirect users to an attacker
            // domain (phishing) via a legitimate-looking dropstart.app link.
            $shop = request('shop');
            if (!preg_match('/^[a-z0-9][a-z0-9\-]*\.myshopify\.com$/i', $shop)) {
                \Log::warning('Shopify install rejected: invalid shop parameter', ['shop' => $shop]);
                return redirect()->route('error')->with([
                    'message' => 'Invalid shop domain'
                ]);
            }

            $scopes = Config::get('shopify-oauth-laravel.scopes');
            $client_id = Config::get('shopify-oauth-laravel.client_id');
            //$redirect_url = Config::get('shopify-oauth-laravel.base_url') . '/shopify-app-auth/load';
			$redirect_url = 'https://' . $domain . '/shopify-app-auth/load';
            $url = 'https://' . $shop . '/admin/oauth/authorize?client_id=' . $client_id . '&scope=' . $scopes . '&redirect_uri=' . $redirect_url . '&host=' . request('host');

            \Log::info('URL for install', ['redirect_url' => $redirect_url, 'url' => $url]);

            return redirect($url);
        } else {
            return redirect()->route('error')->with([
                'message' => 'Something went wrong'
            ]);
        }
    }
}