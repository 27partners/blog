<?php

class sspmod_27partners_Auth_Process_AzureOtherMail extends SimpleSAML_Auth_ProcessingFilter {
  public function process(&$request) {
    assert('is_array($request)');
    assert('array_key_exists("Attributes", $request)');
    assert('array_key_exists("27partners:filter:azure", $request)');

    $attributes =& $request['Attributes'];

    // Copy the 'otherMail' field into the assertion as the mail address
    $mails = $request['27partners:filter:azure']['user']->otherMails;

    if (!is_array($mails) || empty($mails)) {
      return;
    }

    $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] = $mails;
  }
}
