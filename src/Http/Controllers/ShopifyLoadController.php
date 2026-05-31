<?php

namespace joymendonca\ShopifyOauthLaravel\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use App\Models\DemoStore;
use App\Models\Visit;
use App\Models\Client;
use joymendonca\ShopifyOauthLaravel\Facades\ShopifyOauthLaravel;
use Illuminate\Support\Facades\Session;

class ShopifyLoadController extends Controller
{
    public function load(): RedirectResponse
    {
        /* Recover the client refer code from the install cookie when
           the chat-side PHP session got dropped during Shopify's
           OAuth redirect chain (Safari ITP, cross-browser opens).
           Cookie is set on .dropstart.app at /shopify/pre-install,
           so this works for both the chat and dropstart funnels.
           When recovered, we stash into Session::put('refer') so the
           rest of this controller's redirect cascade and the
           downstream user.refer_id update both pick it up. */
        if (!Session::has('refer')) {
            $cookieValue = request()->cookie('shopify_install_context');
            if ($cookieValue) {
                try {
                    $context = decrypt($cookieValue);
                    if (!empty($context['refer_id'])) {
                        Session::put('refer', $context['refer_id']);
                        \Log::info('shopify-load: recovered refer from cookie', [
                            'refer' => $context['refer_id'],
                        ]);
                    }
                } catch (\Throwable $e) {
                    \Log::warning('shopify-load: cookie decrypt failed', ['err' => $e->getMessage()]);
                }
            }
        }

        if (request('code') && request('shop') && request('hmac')) {
			$home = Config::get('shopify-oauth-laravel.app_home_url');
			$app_home_url = $home;

            if(!$this->validateResponse(request('hmac'), request()->getQueryString())){

                \Log::error('HMAC error', ['home-Url' => $app_home_url]);

                return redirect()->route('error')->with([
                    'message' => 'Invalid Request'
                ]);
            }

            $client_id = Config::get('shopify-oauth-laravel.client_id');
            $client_secret = Config::get('shopify-oauth-laravel.client_secret');
			
            $response = Http::post('https://' . request('shop') . '/admin/oauth/access_token?client_id=' . $client_id . '&client_secret=' . $client_secret . '&code=' . request('code'));
            if(isset($response['access_token'])){
                $store = $this->getStoreModelClass()::query()->updateOrCreate([
                    'store_url' => request('shop')
                ],[
                    'store_url' => request('shop'),
                    'access_token' => $response['access_token'],
                    'scope' => $response['scope'],
                ]);

                if(!$user = $this->getUserModelClass()::query()->where('store_url', request('shop'))->first())
                    $user = $this->createUser($store);

                /* Stamp refer onto a freshly-created user when session
                   recovery (or original session) gave us a refer code.
                   Without this, priority-3 in the redirect cascade has
                   nothing to resolve against for first-install users
                   whose chat-side session was wiped — they'd land on
                   the no-refer default funnel even though the cookie
                   carried their attribution. */
                if (isset($user->id) && Session::has('refer') && empty($user->refer_id)) {
                    $user->update(['refer_id' => Session::get('refer')]);
                    \Log::info('Load controller: stamped refer onto new user', [
                        'user_id' => $user->id,
                        'refer'   => Session::get('refer'),
                    ]);
                }

                if (isset($user->id) && isset($store->id)) {
                    if ($this->assignUserToStore($user->id, $store->id)) {
                        Auth::login($user);
                        if(!$store->uninstall_webhook)
                            $this->createUninstallWebhook($store);
                        ShopifyOauthLaravel::setStoreUrl($store->store_url);
                        ShopifyOauthLaravel::callInstallCallback($user, $store);
                        ShopifyOauthLaravel::callLoadCallback($user, $store);
						
                        // Priority 1: Request host — if already on a custom domain, use it directly.
                        // The install controller set redirect_uri to this domain, so it's authoritative.
                        $currentHost = request()->getHost();
                        $domain = null;
                        $resolvedClient = null;

                        if ($currentHost && $currentHost !== 'dropstart.app' && !str_ends_with($currentHost, '.dropstart.app')) {
                            $resolvedClient = Client::whereCustomDomain($currentHost)->first();
                            if ($resolvedClient) {
                                $domain = $currentHost;
                                \Log::info('Load controller: resolved domain from request host', ['domain' => $domain]);
                            }
                        }

                        // Priority 2: Cookie — readable when callback lands on dropstart.app
                        if (!$domain) {
                            $cookieValue = request()->cookie('shopify_install_context');
                            if ($cookieValue) {
                                $context = decrypt($cookieValue);
                                if (isset($context['return_domain'])) {
                                    $domain = $context['return_domain'];
                                    \Log::info('Load controller: resolved domain from cookie', ['domain' => $domain]);
                                }
                            }
                        }

                        // Priority 3: user->refer_id — last resort for direct-from-Shopify-admin loads
                        // when both the request host (Priority 1) and the install cookie
                        // (Priority 2) failed to produce a domain. Always restore session
                        // refer so the downstream /setup render resolves the client correctly
                        // for non-custom-domain clients (Tradelle etc.) too — previously this
                        // block silently no-op'd for them and dropped them into client_id=3.
                        if (!$domain && $user->refer_id) {
                            $resolvedClient = Client::where('refer', $user->refer_id)->first();
                            if ($resolvedClient) {
                                Session::put('refer', $user->refer_id);
                                if ($resolvedClient->custom_domain) {
                                    $domain = $resolvedClient->primary_domain;
                                    \Log::info('Load controller: resolved domain from user refer_id', ['domain' => $domain, 'refer_id' => $user->refer_id]);
                                } else {
                                    \Log::info('Load controller: restored session refer from user.refer_id (no custom domain)', ['refer_id' => $user->refer_id]);
                                }
                            }
                        }

                        // Build the redirect URL from the resolved domain.
                        // Brands whose canonical funnel is /go skip the
                        // standard $home (/setup) path. Keep this list in
                        // sync with App\Http\Middleware\RedirectGoFunnelDomains.
                        if ($domain) {
                            $goDomains = ['go.ecomwebsites.com', 'launch.ecomwebsites.com', 'start.ecomwebsites.com'];
                            if (in_array($domain, $goDomains, true)) {
                                $app_home_url = "https://{$domain}/go";
                            } else {
                                $app_home_url = "https://{$domain}{$home}";
                            }
                        }

                        // Update user.refer_id to keep it current for future direct-from-Shopify loads
                        if ($domain && !$resolvedClient) {
                            $resolvedClient = Client::whereCustomDomain($domain)->first();
                        }
                        if ($resolvedClient && $resolvedClient->refer && $user->refer_id !== $resolvedClient->refer) {
                            $oldReferId = $user->refer_id;
                            $user->update(['refer_id' => $resolvedClient->refer]);
                            \Log::info('Load controller: updated user refer_id', ['user_id' => $user->id, 'old_refer_id' => $oldReferId, 'new_refer_id' => $resolvedClient->refer]);
                        }
                    }
                }
				
				$ds = DemoStore::where("store_url", $store->store_url)->first();
				
				if ($ds) {
					$ds->update([
						"shopify_token" => $response['access_token'],
						"token_updated" => date("Y-m-d H:i:s")
					]);
					$app_home_url = "https://portal.dropstart.app/admin/demo-stores/{$ds->id}/edit";
				}
				
                return redirect($app_home_url);
            } else {
                return redirect()->route('error')->with([
                    'message' => 'Access token not received'
                ]);
            }
        } else {
            return redirect()->route('error')->with([
                'message' => 'Something went wrong'
            ]);
        }
    }

    protected function validateResponse($hmac, $query_string)
    {
        $client_secret = Config::get('shopify-oauth-laravel.client_secret');
        $query_without_hmac = str_replace('hmac='. $hmac . '&', '', $query_string);
        $calculated_hmac = hash_hmac('sha256', $query_without_hmac, $client_secret);
        // Constant-time comparison to avoid HMAC timing oracles.
        return hash_equals($calculated_hmac, $hmac);
    }

    protected function createUser($store)
    {
        $api_version = Config::get('shopify-oauth-laravel.api_version');
        $response = Http::withHeader('X-Shopify-Access-Token', $store->access_token)->get('https://' . $store->store_url . '/admin/api/' . $api_version . '/shop.json');
        
        if(isset($response['shop'])){
            return $this->getUserModelClass()::query()->updateOrCreate([
                'email' => isset($response['shop']['email']) ? $response['shop']['email'] : 'store@' . $store->store_url,
            ], [
                'email' => isset($response['shop']['email']) ? $response['shop']['email'] : 'store@' . $store->store_url,
                'name' => isset($response['shop']['name']) ? $response['shop']['name'] : null,
                'store_url' => $store->store_url
            ]);
        }
    }
    protected function assignUserToStore($user_id, $store_id): bool
    {
        $store_has_users = Config::get('shopify-oauth-laravel.tables.store_has_users');
        if (DB::table($store_has_users)
            ->where('store_id', $store_id)
            ->where('user_id', $user_id)
            ->exists())
            return true;

        return DB::table($store_has_users)->insert([
            'store_id' => $store_id,
            'user_id' => $user_id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function createUninstallWebhook($store)
    {
        $data['webhook'] = [
            'address' => Config::get('shopify-oauth-laravel.base_url') . '/shopify-app-auth/uninstall',
            'topic' => 'app/uninstalled',
            'format' => 'json',
        ];
        $api_version = Config::get('shopify-oauth-laravel.api_version');
        $response = Http::withHeader('X-Shopify-Access-Token', $store->access_token)->post('https://' . $store->store_url . '/admin/api/' . $api_version . '/webhooks.json', $data);
        
        if(isset($response['webhook']['id'])){
            $this->getStoreModelClass()::query()->where('id',$store->id)->update([
                'uninstall_webhook' => $response['webhook']['id']
            ]);
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