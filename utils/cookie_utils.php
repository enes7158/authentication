<?php
function getCookieSecretKey() {
    global $COOKIE_SECRET_KEY;

    if (empty($COOKIE_SECRET_KEY)) {
        die("Cookie güvenlik anahtarı tanımlanmamış. Lütfen config.php dosyasını kontrol edin.");
    }
    return $COOKIE_SECRET_KEY;
}

function hashCookieValue($value, ?string $secret_key = null)
{
    if ($secret_key === null) $secret_key = getCookieSecretKey();
    return hash_hmac('sha256', $value, $secret_key);
}

function setSecureCookie($name, $value, $expiry, $path = '/', $domain = '', $secure = false, $httponly = true) {
    $hash = hashCookieValue($value);

    $cookie_data = [
        'value' => $value,
        'hash' => $hash
    ];

    $cookie_value = base64_encode(json_encode($cookie_data));

    return setcookie($name, $cookie_value, [
        'expires' => $expiry,
        'path' => $path,
        'domain' => $domain,
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => 'Lax'
    ]);
}

function getSecureCookie($name) {
    if (!isset($_COOKIE[$name])) {
        return null;
    }

    try {
        $data = json_decode(base64_decode($_COOKIE[$name]), true);

        if (!isset($data['value']) || !isset($data['hash'])) {
            return null;
        }

        $expected_hash = hashCookieValue($data['value']);

        if (hash_equals($expected_hash, $data['hash'])) {
            return $data['value'];
        }
    } catch (Exception) {
        return null;
    }
    return null;
}

function deleteSecureCookie($name,$path = '/',$domain = ''){
    return setcookie($name, '', time() - 3600, $path, $domain);
}

function generateResetToken($length = 32) {
    return bin2hex(random_bytes($length/2));
}
function saveResetToken($db, $userId, $token, $expireHours = 1) {
    $deleteStmt = $db->prepare("DELETE FROM password_resets WHERE user_id = :user_id");
    $deleteStmt->bindParam(':user_id', $userId);
    $deleteStmt->execute();

    $expires_at = date("Y-m-d H:i:s", time() + ($expireHours * 3600));

    $insertStmt = $db->prepare("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?,?,?)");
    return $insertStmt->execute([$userId, $token, $expires_at]);
}
function validateResetToken($db, $token) {
    $stmt = $db->prepare("SELECT user_id, expires_at FROM password_resets WHERE token = ? LIMIT 1");
    $stmt->execute([$token]);

    if($reset = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $currentTime = time();
        $tokenTime = strtotime($reset['expires_at']);

        if ($currentTime <=  $tokenTime) {
            return $reset;
        }
    }
    return false;
}

function deleteResetToken($db, $userId) {
    $stmt = $db->prepare("DELETE FROM password_resets WHERE user_id = ?");
    return $stmt->execute([$userId]);
}

function resetPasswordAndLogin($db, $userId, $newPassword, $cookieName = "user_id", $cookieExpiry = 2592000) {
    $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
    $db->beginTransaction();

    try {
        $updateStmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
        $updateStmt->execute([$hashedPassword, $userId]);

        $deleteStmt = $db->prepare("DELETE FROM password_resets WHERE user_id = ?");
        $deleteStmt->execute([$userId]);

        $sessionId = generateResetToken(32);
        $expiry = time() + $cookieExpiry;
        $expiryDate = date('Y-m-d H:i:s', $expiry);

        $cookieStmt = $db->prepare("INSERT INTO auth_cookies (user_id, cookie_id, expires_at) VALUES (?, ?, ?)");
        $cookieStmt->execute([$userId, $sessionId, $expiryDate]);

        setSecureCookie($cookieName, $userId, $expiry);

        $db->commit();
        return true;
    } catch (Exception $e) {
        $db->rollBack();
        error_log("Şifre sıfırlama hatası: " . $e->getMessage());
        return false;
    }
}
function sendPasswordResetEmail($email, $username, $token, $resetUrl = "http://auth-system.test/auth/reset_password.php?token=%s") {
    require_once __DIR__ . '/../vendor/autoload.php';

    $smtp_host = $_ENV['SMTP_HOST'];
    $smtp_port = $_ENV['SMTP_PORT'];
    $smtp_username = $_ENV['SMTP_USERNAME'];
    $smtp_password = $_ENV['SMTP_PASSWORD'];
    $smtp_from_email = $_ENV['SMTP_FROM_EMAIL'];
    $smtp_from_name = $_ENV['SMTP_FROM_NAME'];

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host = $smtp_host;
        $mail->SMTPAuth = true;
        $mail->Username = $smtp_username;
        $mail->Password = $smtp_password;
        $mail->SMTPSecure = 'tls';
        $mail->Port = $smtp_port;
        $mail->CharSet = 'UTF-8';

        $mail->setFrom($smtp_from_email, $smtp_from_name);
        $mail->addAddress($email);

        $subject = "Şifre Sıfırlama Talebi";
        $resetLink = sprintf($resetUrl, $token);

        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = "
        <html>
        <body style='font-family: Arial, sans-serif; line-height: 1.6;'>
            <h2>Merhaba {$username},</h2>
            <p>{$resetLink}</p>
        </body>
        </html>
        ";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("E-posta gönderme hatası: " . $mail->ErrorInfo);
        return false;
    }
}