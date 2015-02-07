<?php

class sspmod_27partners_Auth_Process_AzureGroups extends SimpleSAML_Auth_ProcessingFilter {
  public function process(&$request) {
    assert('is_array($request)');
    assert('array_key_exists("Attributes", $request)');
    assert('array_key_exists("27partners:filter:azure", $request)');

    $attributes =& $request['Attributes'];

    // Copy the groups into the assertion
    foreach ($request['27partners:filter:azure']['group']->value as $group) {
      if ($group->objectType != 'Group') {
        continue;
      }
      $groups[] = $group->displayName;
    }

    $attributes['http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'] = $groups;
  }
}
