<?php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/cookie_utils.php';

deleteSecureCookie('user_id', '/');
deleteSecureCookie('username', '/');

header("Location: login.php");
exit;
