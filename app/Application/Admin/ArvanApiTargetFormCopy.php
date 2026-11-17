<?php

namespace App\Application\Admin;

/**
 * Native Admin form labels and actionable validation copy for the two
 * ArvanCloud Target forms. No network, credential, or authorization decisions.
 */
final class ArvanApiTargetFormCopy
{
    /** @return array<string,string> */
    public static function messages(): array
    {
        return [
            'api_base_url.required' => __('Enter the HTTPS API base URL for the selected ArvanCloud product.'),
            'api_base_url.url' => __('Enter a valid HTTPS API base URL, such as https://napi.arvancloud.ir/cdn/4.0.'),
            'api_spec_url.url' => __('Enter a valid HTTPS URL for the optional OpenAPI description.'),
            'api_probe_path.starts_with' => __('The read-only GET probe path must begin with /, such as /domains.'),
            'api_key.required' => __('Paste the Machine User API key from ArvanCloud.'),
        ];
    }

    /** @return array<string,string> */
    public static function attributes(): array
    {
        return [
            'api_base_url' => __('API base URL'),
            'api_spec_url' => __('OpenAPI description URL'),
            'api_probe_path' => __('read-only GET probe path'),
            'api_key' => __('Machine User API key'),
        ];
    }
}
