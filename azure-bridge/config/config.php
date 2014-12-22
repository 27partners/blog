<?php

$config = array(

    'baseurlpath'            => 'azure/',
    'auth.adminpassword'     => '1234',
    'secretsalt'             => 'upa45rgvfb84dttjg5po29hkcmw03t0e',
    'technicalcontact_name'  => 'Technical Contact',
    'technicalcontact_email' => 'support@example.com',

    'admin.protectindexpage' => true,
    'logging.handler'        => 'errorlog',

    'enable.saml20-idp' => true,

    'authproc.sp' => array(
      50 => array(
        'class'        => '27partners:AzureGroups',
        'clientid'     => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        'clientsecret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'tenantid'     => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
      ),
    ),

    'metadata.sources' => array(
      array('type' => 'flatfile'),
      array('type' => 'xml', 'file' => 'metadata/application-service-provider.xml'),
      array('type' => 'xml', 'file' => 'metadata/login.windows.net.xml'),
    ),
);
