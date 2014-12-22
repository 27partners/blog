<?php

$config = array(
  'admin' => array(
    'core:AdminPassword',
  ),
  'default-sp' => array(
    'saml:SP',
    'privatekey'  => 'saml.pem',
    'certificate' => 'saml.crt',
    'idp'         => 'https://sts.windows.net/5ba82ddd-4a75-4e30-be5d-4c642728a95d/',
  ),
);
