<?php

class sspmod_27partners_Auth_Process_Azure extends SimpleSAML_Auth_ProcessingFilter {
  private $clientid;
  private $clientsecret;
  private $tenantid;

  public function __construct($config, $reserved) {
    parent::__construct($config, $reserved);
    assert('is_array($config)');

    foreach (array('clientid', 'clientsecret', 'tenantid') as $attr) {
      $this->$attr = $config[$attr];
    }
  }

  public function process(&$request) {
    assert('is_array($request)');
    assert('array_key_exists("Attributes", $request)');

    require_once(dirname(__FILE__) . '/../../httpful.phar');

    $groups = array();
    $attributes =& $request['Attributes'];

    SimpleSAML_Logger::debug('Loading Azure AD for user ' . $attributes['http://schemas.microsoft.com/identity/claims/objectidentifier'][0]);

    // Log into the Azure AD API
    $token = Httpful\Request::post(
      sprintf('https://login.windows.net/%s/oauth2/token?api-version=1.0',
        $this->tenantid
      ), http_build_query(array(
        'grant_type'    => 'client_credentials',
        'client_id'     => $this->clientid,
        'client_secret' => $this->clientsecret,
        'resource'      => 'https://graph.windows.net'
      )
    ))->send();

    $this->checkresponse($token, "Unable to log into Azure");

    // Create the request template
    $template = Httpful\Request::init()->expectsJson()->addHeader(
      'Authorization', 'Bearer ' . $token->body->access_token
    );
    Httpful\Request::ini($template);

    $userid = $attributes['http://schemas.microsoft.com/identity/claims/objectidentifier'][0];

    // Fetch user
    $user = Httpful\Request::get(
      sprintf('https://graph.windows.net/%s/users/%s?api-version=1.5',
        $this->tenantid,
        $userid
      )
    )->send();

    $this->checkresponse($user, "Unable to fetch data for user $userid");

    // Fetch groups
    $groupmembership = Httpful\Request::get(
      sprintf('https://graph.windows.net/%s/users/%s/memberOf?api-version=1.5',
        $this->tenantid,
        $userid
      )
    )->send();

    $this->checkresponse($groupmembership, "Unable to fetch group membership for user $userid");

    // Make this information available for other authentication processors
    $request['27partners:filter:azure'] = array(
      'user'  => $user->body,
      'group' => $groupmembership->body,
    );
  }

  // Check the status of an Azure API response
  private function checkresponse($response, $message) {
    if ($response && ($response->code == 200) && $response->body) {
      return;
    }

    $azuremsg = 'No data returned from Azure';

    if ($response->body) {
      if (property_exists($response->body, 'error_description')) {
        $azuremsg = $response->body->error_description;
      }
      if (property_exists($response->body, 'odata.error')) {
        $azuremsg = $response->body->{'odata.error'}->message->value;
      }
    }

    throw new SimpleSAML_Error_Exception(sprintf('Azure Error: "%s", http:%s, azure:"%s"',
      $message,
      $response->code,
      $azuremsg
    ));
  }
}
